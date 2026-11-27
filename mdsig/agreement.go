package mdsig

import (
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// --- require (SPEC 5.8)

const (
	OrderPending = "pending"
	OrderGuide   = "guide"
	OrderStrict  = "strict"
)

type RequirementAttributes struct {
	Role         string
	UserVerified bool
	MemberOf     string
	Pubkey       string
}

type Requirement struct {
	Method     string
	Signer     string
	Pattern    bool
	Attributes RequirementAttributes
	DeclaredBy int
	Step       int
	// m of "step any=m"; 0 when every line of the step is needed
	Any int
	// 1-based line of the require value
	Line int
}

func (r Requirement) String() string {
	parts := []string{r.Method + ":" + r.Signer}
	a := r.Attributes
	if a.Role != "" {
		parts = append(parts, "role="+a.Role)
	}
	if a.UserVerified {
		parts = append(parts, "user_verified")
	}
	if a.MemberOf != "" {
		parts = append(parts, "member_of="+a.MemberOf)
	}
	if a.Pubkey != "" {
		parts = append(parts, "pubkey="+a.Pubkey)
	}
	return strings.Join(parts, " ")
}

type RequireStep struct {
	Step  int
	Any   int
	Lines []Requirement
}

type RequireSpec struct {
	Order string
	Steps []RequireStep
}

type ParsedRequire struct {
	Spec         RequireSpec
	Requirements []Requirement
	// the declaring block is malformed
	Errors []string
	// unknown attributes or methods: the block stays valid, the agreement is "unsupported"
	Unsupported []string
	// SPEC 5.8.10: over the interoperability limits; the agreement is "undetermined"
	OverLimit string
	// advice for older syntax; never changes a verdict
	Hints []string
}

var requireMethods = map[string]bool{"dns": true, "git-hosting": true, "tofu": true, "pgp": true, "directory": true}

// SPEC 5.8.10: minimum limits every verifier supports
const (
	maxRequireLines = 64
	maxRequireSteps = 16
)

var (
	reqAttrs           = map[string]string{"role": listAttrValue, "user_verified": listAttrFlag, "member_of": listAttrValue, "pubkey": listAttrValue}
	methodRe           = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	countRe            = regexp.MustCompile(`^[1-9][0-9]{0,3}$`)
	legacyOrderRe      = regexp.MustCompile(`^order (pending|guide|strict)$`)
	legacyStepRe       = regexp.MustCompile(`^step [1-9][0-9]*(?: any ([1-9][0-9]*))?$`)
	rosterURLRe        = regexp.MustCompile(`^https://([^/?#@:]*)(?::([0-9]*))?([/?][^#]*)?$`)
	userVerifiedMethod = map[string]bool{"dns": true, "directory": true, "tofu": true}
)

type rosterRef struct {
	https  bool
	url    string
	host   string
	domain string
}

// SPEC 5.8.8: https URL without userinfo, fragment, or a port other than 443; the host is an ldh-domain
func parseRosterRef(v string) (rosterRef, bool) {
	if d, ok := strings.CutPrefix(v, "dns:"); ok {
		return rosterRef{domain: d}, isLdhDomain(d)
	}
	m := rosterURLRe.FindStringSubmatchIndex(v)
	if m == nil {
		return rosterRef{}, false
	}
	host := v[m[2]:m[3]]
	if !isLdhDomain(host) {
		return rosterRef{}, false
	}
	if m[4] >= 0 && v[m[4]:m[5]] != "443" {
		return rosterRef{}, false
	}
	return rosterRef{https: true, url: v, host: host}, true
}

func checkPattern(method, signer string) string {
	if signer == "*" {
		if method == "tofu" {
			return "tofu has no patterns"
		}
		return ""
	}
	if method == "dns" && strings.HasPrefix(signer, "*.") && isLdhDomain(signer[2:]) {
		return ""
	}
	if (method == "directory" || method == "pgp") && strings.HasPrefix(signer, "*@") && isLdhDomain(signer[2:]) {
		return ""
	}
	return fmt.Sprintf("%q is not one of the patterns dns:*, dns:*.<domain>, directory:*, directory:*@<domain>, pgp:*, pgp:*@<domain>, git-hosting:*", method+":"+signer)
}

func ParseRequire(value string, declaredBy int) *ParsedRequire {
	p := &ParsedRequire{Spec: RequireSpec{Order: OrderPending}}
	raws := strings.Split(value, "\n")
	var steps []*RequireStep
	var implicit *RequireStep
	errf := func(format string, a ...any) { p.Errors = append(p.Errors, fmt.Sprintf(format, a...)) }
	for i, raw := range raws {
		lineNo := i + 1
		text := strings.TrimLeft(raw, " ")
		word, _, _ := strings.Cut(text, " ")
		if strings.Contains(raw, "\t") {
			p.Hints = append(p.Hints, fmt.Sprintf("require line %d: tabs are not allowed; indent with spaces", lineNo))
		}
		switch word {
		case "order":
			if legacyOrderRe.MatchString(text) {
				p.Hints = append(p.Hints, fmt.Sprintf("require line %d: write \"order mode=%s\" (format 0.1)", lineNo, text[6:]))
			}
			if i != 0 {
				errf("require line %d: \"order\" must be the first line", lineNo)
				continue
			}
			l, e := parseListLine(raw, map[string]string{"mode": listAttrValue})
			if l == nil {
				errf("require line %d: %s", lineNo, e)
				continue
			}
			if len(l.unknown) > 0 {
				p.Unsupported = append(p.Unsupported, fmt.Sprintf("require line %d: unknown attribute %q", lineNo, l.unknown[0]))
				continue
			}
			mode, _ := l.get("mode")
			if mode.value != OrderPending && mode.value != OrderGuide && mode.value != OrderStrict {
				errf("require line %d: expected \"order mode=pending|guide|strict\"", lineNo)
				continue
			}
			p.Spec.Order = mode.value
			continue
		case "step":
			if m := legacyStepRe.FindStringSubmatch(text); m != nil {
				anyPart := ""
				if m[1] != "" {
					anyPart = " any=" + m[1]
				}
				p.Hints = append(p.Hints, fmt.Sprintf("require line %d: write \"step%s\"; steps are numbered by their position (format 0.1)", lineNo, anyPart))
			}
			if implicit != nil {
				errf("require line %d: a requirement line cannot come before the first \"step\" line", lineNo)
				continue
			}
			l, e := parseListLine(raw, map[string]string{"any": listAttrValue})
			if l == nil {
				errf("require line %d: %s", lineNo, e)
				continue
			}
			if len(l.unknown) > 0 {
				p.Unsupported = append(p.Unsupported, fmt.Sprintf("require line %d: unknown attribute %q", lineNo, l.unknown[0]))
				continue
			}
			n := 0
			if a, ok := l.get("any"); ok {
				if !countRe.MatchString(a.value) {
					errf("require line %d: any= needs a count from 1 to 9999", lineNo)
					continue
				}
				n, _ = strconv.Atoi(a.value)
			}
			steps = append(steps, &RequireStep{Step: len(steps) + 1, Any: n})
			continue
		}
		l, e := parseListLine(raw, reqAttrs)
		if l == nil {
			errf("require line %d: %s", lineNo, e)
			continue
		}
		var target *RequireStep
		if len(steps) > 0 {
			target = steps[len(steps)-1]
		} else {
			if implicit == nil {
				implicit = &RequireStep{Step: 1}
			}
			target = implicit
		}
		method, signer := "", ""
		if c := strings.IndexByte(l.target, ':'); c > 0 {
			method, signer = l.target[:c], l.target[c+1:]
		}
		if !methodRe.MatchString(method) || signer == "" {
			errf("require line %d: expected \"<method>:<signer> [attribute ...]\", got %s", lineNo, jsonString(raw))
			continue
		}
		if method == "tsa" {
			errf("require line %d: a tsa block cannot be required", lineNo)
			continue
		}
		if len(l.unknown) > 0 {
			if len(l.unknown) == 1 && len(l.attrs) == 1 && roleRe.MatchString(l.unknown[0]) {
				p.Hints = append(p.Hints, fmt.Sprintf("require line %d: write the role as \"role=%s\" (format 0.1)", lineNo, l.unknown[0]))
			}
			p.Unsupported = append(p.Unsupported, fmt.Sprintf("require line %d: unknown attribute %q", lineNo, l.unknown[0]))
			continue
		}
		if !requireMethods[method] {
			p.Unsupported = append(p.Unsupported, fmt.Sprintf("require line %d: unknown method %q", lineNo, method))
			continue
		}
		pattern := strings.Contains(signer, "*")
		var se string
		if pattern {
			se = checkPattern(method, signer)
		} else {
			se = CheckSignerID(method, signer)
		}
		if se != "" {
			errf("require line %d: %s", lineNo, se)
			continue
		}
		var attrs RequirementAttributes
		if role, ok := l.get("role"); ok {
			if !roleRe.MatchString(role.value) {
				errf("require line %d: role must match [a-z0-9][a-z0-9._-]*", lineNo)
				continue
			}
			attrs.Role = role.value
		}
		if pk, ok := l.get("pubkey"); ok {
			if method != "tofu" {
				errf("require line %d: pubkey= is only allowed on tofu lines", lineNo)
				continue
			}
			kt, _, ok := decodeKeyValue(pk.value)
			if !ok || (kt != "ed25519" && kt != "es256") {
				errf("require line %d: pubkey= must be ed25519:<base64> or es256:<base64>", lineNo)
				continue
			}
			attrs.Pubkey = pk.value
		}
		if _, ok := l.get("user_verified"); ok {
			if !userVerifiedMethod[method] {
				errf("require line %d: user_verified is only allowed on dns, directory, and tofu lines", lineNo)
				continue
			}
			// SPEC 5.8.2: anyone can make a tofu key, so the key has to be pinned
			if method == "tofu" && attrs.Pubkey == "" {
				errf("require line %d: user_verified on a tofu line needs pubkey=", lineNo)
				continue
			}
			attrs.UserVerified = true
		}
		if mo, ok := l.get("member_of"); ok {
			if method == "tofu" {
				errf("require line %d: member_of is not allowed on tofu lines", lineNo)
				continue
			}
			if _, ok := parseRosterRef(mo.value); !ok {
				errf("require line %d: member_of must be an https URL (no userinfo, fragment, or port other than 443) or dns:<domain>", lineNo)
				continue
			}
			attrs.MemberOf = mo.value
		}
		target.Lines = append(target.Lines, Requirement{Method: method, Signer: signer, Pattern: pattern, Attributes: attrs, DeclaredBy: declaredBy, Step: target.Step, Any: target.Any, Line: lineNo})
	}
	if implicit != nil {
		steps = append(steps, implicit)
	}
	if len(steps) == 0 && len(p.Errors) == 0 && len(p.Unsupported) == 0 {
		p.Errors = append(p.Errors, "require: no requirement lines")
	}
	for _, s := range steps {
		if len(s.Lines) == 0 {
			if len(p.Unsupported) == 0 {
				errf("require: step %d has no requirement", s.Step)
			}
			continue
		}
		hasPattern := false
		named := map[string]bool{}
		for _, l := range s.Lines {
			hasPattern = hasPattern || l.Pattern
			named[l.Method+":"+l.Signer] = true
		}
		// SPEC 5.8.1 rule 6: m distinct signers must be possible
		if s.Any != 0 && !hasPattern && s.Any > len(named) {
			errf("require: step %d asks for any=%d of %d different signers", s.Step, s.Any, len(named))
		}
		if s.Any == 0 {
			// SPEC 5.8.1 rule 7: one signer counts once per step, so two lines only it can fill can never both be met
			seen := map[string]bool{}
			for _, l := range s.Lines {
				if l.Pattern {
					continue
				}
				id := l.Method + ":" + l.Signer
				if seen[id] {
					errf("require: %s appears twice in step %d, which has no any=", id, s.Step)
				}
				seen[id] = true
			}
		}
	}
	// SPEC 5.8.6: anyone can append a block, so under strict a pattern line would let a stranger cause a violation
	if p.Spec.Order == OrderStrict && slices.ContainsFunc(steps, func(s *RequireStep) bool {
		return slices.ContainsFunc(s.Lines, func(l Requirement) bool { return l.Pattern })
	}) {
		p.Errors = append(p.Errors, "require: order mode=strict cannot be used with pattern lines")
	}
	switch {
	case len(raws) > maxRequireLines:
		p.OverLimit = fmt.Sprintf("require has %d lines (verifiers need to support only %d)", len(raws), maxRequireLines)
	case len(steps) > maxRequireSteps:
		p.OverLimit = fmt.Sprintf("require has %d steps (verifiers need to support only %d)", len(steps), maxRequireSteps)
	}
	p.Spec.Steps = make([]RequireStep, len(steps))
	p.Requirements = []Requirement{}
	for i, s := range steps {
		p.Spec.Steps[i] = *s
		p.Requirements = append(p.Requirements, s.Lines...)
	}
	return p
}

// --- evaluation

const (
	MembershipMember      = "member"
	MembershipNotMember   = "not-member"
	MembershipUnavailable = "unavailable"
)

type membershipOracle func(roster, id string) string

type agreementBlock struct {
	Index  int
	Status string
	Code   string
	Fields map[string]string
	// WebAuthn UP and UV flags both set (SPEC 5.8)
	UserVerified bool
}

const (
	RejectEarly             = "early"
	RejectBlocked           = "blocked"
	RejectNotMember         = "not-member"
	RejectRosterUnavailable = "roster-unavailable"
	RejectNotUserVerified   = "not-user-verified"
	RejectKeyMismatch       = "key-mismatch"
	RejectSelf              = "self"
	RejectScoped            = "scoped"
	RejectUnresolved        = "unresolved"
	RejectNotValid          = "not-valid"
)

type Rejection struct {
	Index int
	// not a block code (SPEC 5.8.9)
	Reason string
}

type MissingRequirement struct {
	Requirement
	Need int
	// the first step of this declaration that is not complete, when it holds this one back; 0 when none
	BlockedBy int
	Rejected  []Rejection
}

type OrderViolation struct {
	DeclaredBy int
	Step       int
	Line       int
	Index      int
	Method     string
	Signer     string
	Order      string
}

type Satisfaction struct {
	DeclaredBy, Step, Line, Index int
}

type LaterStep struct {
	Step  int
	Need  int
	Lines []Requirement
}

type NextStep struct {
	DeclaredBy int
	Step       int
	Need       int
	Candidates []Requirement
	Later      []LaterStep
}

type StepLine struct {
	Line   int
	Blocks []int
}

type DeclarationStep struct {
	Step      int
	Any       int
	Need      int
	Count     int
	Complete  bool
	BlockedBy int
	Lines     []StepLine
}

type Declaration struct {
	DeclaredBy int
	Order      string
	Status     string
	Detail     string
	Steps      []DeclarationStep
}

const (
	AgreementNone         = "none"
	AgreementComplete     = "complete"
	AgreementPending      = "pending"
	AgreementViolated     = "violated"
	AgreementUndetermined = "undetermined"
	AgreementUnsupported  = "unsupported"
)

type Agreement struct {
	Status       string
	Required     []Requirement
	Missing      []MissingRequirement
	Violations   []OrderViolation
	Next         []NextStep
	Satisfied    []Satisfaction
	Declarations []Declaration
}

func emptyAgreement() Agreement {
	return Agreement{Status: AgreementNone, Required: []Requirement{}, Missing: []MissingRequirement{}, Violations: []OrderViolation{},
		Next: []NextStep{}, Satisfied: []Satisfaction{}, Declarations: []Declaration{}}
}

func idOf(f map[string]string) string { return f["method"] + ":" + f["signer"] }

func targetMatches(r Requirement, f map[string]string) bool {
	if f["method"] != r.Method {
		return false
	}
	s := f["signer"]
	if !r.Pattern {
		return s == r.Signer
	}
	if r.Signer == "*" {
		return true
	}
	// SPEC 5.8.3: label boundaries; "*." excludes the domain itself, "*@" excludes subdomains
	if strings.HasPrefix(r.Signer, "*.") {
		return strings.HasSuffix(s, r.Signer[1:])
	}
	if strings.HasPrefix(r.Signer, "*@") {
		i := strings.LastIndexByte(s, '@')
		return i >= 0 && s[i:] == r.Signer[1:]
	}
	return false
}

// first failing attribute, or ""; "role" means the block does not name this line at all
func attributeFailure(r Requirement, b agreementBlock, oracle membershipOracle) string {
	a := r.Attributes
	if a.Role != "" {
		if role, ok := b.Fields["role"]; !ok || role != a.Role {
			return "role"
		}
	}
	if a.Pubkey != "" {
		if pk, ok := b.Fields["pubkey"]; !ok || !sameKeyValue(a.Pubkey, pk) {
			return RejectKeyMismatch
		}
	}
	if a.UserVerified && !(b.Fields["alg"] == "webauthn-es256" && b.UserVerified) {
		return RejectNotUserVerified
	}
	if a.MemberOf != "" {
		switch oracle(a.MemberOf, idOf(b.Fields)) {
		case MembershipNotMember:
			return RejectNotMember
		case MembershipUnavailable:
			return RejectRosterUnavailable
		}
	}
	return ""
}

const infinity = math.MaxInt

type assignment struct {
	signer string
	line   int
	block  int
}

type stepOutcome struct {
	// the completion point k of the step on its own; 0 when it is not complete
	k        int
	assigned []assignment
	size     int
	need     int
	// signers with an edge to a named line (SPEC 5.8.6: guide reports only those)
	namedEdge map[string]bool
}

func lineCap(s RequireStep, l Requirement) int {
	if s.Any != 0 && l.Pattern {
		return infinity
	}
	return 1
}

// SPEC Appendix C assign(): edges signer -> line represented by the earliest qualifying block; augmenting paths in canonical order
func matchStep(step RequireStep, eligible []agreementBlock, qualifies func(agreementBlock, Requirement) bool) stepOutcome {
	lines := step.Lines
	need := step.Any
	if need == 0 {
		need = len(lines)
	}
	var order []string
	rep := map[string][]int{}
	namedEdge := map[string]bool{}
	for _, b := range eligible {
		id := idOf(b.Fields)
		r, ok := rep[id]
		if !ok {
			r = make([]int, len(lines))
			rep[id] = r
			order = append(order, id)
		}
		for j, l := range lines {
			if r[j] == 0 && qualifies(b, l) {
				r[j] = b.Index
				if !l.Pattern {
					namedEdge[id] = true
				}
			}
		}
	}
	assign := func(limit int) map[string]int {
		owner := make([][]string, len(lines))
		lineOf := map[string]int{}
		var augment func(x string, seen map[int]bool) bool
		augment = func(x string, seen map[int]bool) bool {
			r := rep[x]
			for j := range lines {
				if r[j] == 0 || r[j] > limit || seen[j] {
					continue
				}
				seen[j] = true
				if len(owner[j]) < lineCap(step, lines[j]) {
					owner[j] = append(owner[j], x)
					lineOf[x] = j
					return true
				}
				for _, y := range slices.Clone(owner[j]) {
					if augment(y, seen) {
						owner[j] = append(slices.DeleteFunc(slices.Clone(owner[j]), func(z string) bool { return z == y }), x)
						lineOf[x] = j
						return true
					}
				}
			}
			return false
		}
		for _, x := range order {
			if len(lineOf) == need {
				break
			}
			if slices.ContainsFunc(rep[x], func(p int) bool { return p != 0 && p <= limit }) {
				augment(x, map[int]bool{})
			}
		}
		return lineOf
	}
	var positions []int
	for _, b := range eligible {
		if !slices.Contains(positions, b.Index) {
			positions = append(positions, b.Index)
		}
	}
	sort.Ints(positions)
	k := 0
	var final map[string]int
	for _, p := range positions {
		final = assign(p)
		if len(final) == need {
			k = p
			break
		}
	}
	if k == 0 {
		final = assign(infinity)
	}
	assigned := make([]assignment, 0, len(final))
	for signer, j := range final {
		assigned = append(assigned, assignment{signer: signer, line: j, block: rep[signer][j]})
	}
	sort.Slice(assigned, func(a, b int) bool {
		la, lb := lines[assigned[a].line].Line, lines[assigned[b].line].Line
		if la != lb {
			return la < lb
		}
		return assigned[a].block < assigned[b].block
	})
	return stepOutcome{k: k, assigned: assigned, size: len(final), need: need, namedEdge: namedEdge}
}

func isUndeterminedCode(code string) bool { return code == KindNetwork || code == KindOffline }

type declarationResult struct {
	status     string
	missing    []MissingRequirement
	violations []OrderViolation
	satisfied  []Satisfaction
	next       *NextStep
	detail     string
	steps      []DeclarationStep
}

// SPEC 5.8.5, 5.8.6 and Appendix C evaluate()
func evaluateDeclaration(decl agreementBlock, parsed *ParsedRequire, blocks []agreementBlock, oracle membershipOracle) declarationResult {
	spec := parsed.Spec
	d := decl.Index
	declID := idOf(decl.Fields)
	var later []agreementBlock
	for _, b := range blocks {
		if b.Index > d {
			later = append(later, b)
		}
	}
	sort.SliceStable(later, func(i, j int) bool { return later[i].Index < later[j].Index })
	used := map[int]bool{}
	res := declarationResult{}
	var outcomes []stepOutcome
	prev := d
	firstIncomplete := 0
	var causes []string
	addCause := func(c string) {
		if !slices.Contains(causes, c) {
			causes = append(causes, c)
		}
	}
	qualifies := func(b agreementBlock, l Requirement) bool {
		return targetMatches(l, b.Fields) && !(l.Pattern && idOf(b.Fields) == declID) && attributeFailure(l, b, oracle) == ""
	}
	// SPEC 5.8.9: the first reason that applies, in this order
	rejectReason := func(b agreementBlock, l Requirement, usedBefore map[int]bool, start int) string {
		if b.Status == StatusUnresolved {
			return RejectUnresolved
		}
		if b.Status != StatusValid {
			return RejectNotValid
		}
		if _, ok := b.Fields["scope"]; ok {
			return RejectScoped
		}
		if l.Pattern && idOf(b.Fields) == declID {
			return RejectSelf
		}
		switch f := attributeFailure(l, b, oracle); f {
		case "role":
			return ""
		case "":
		default:
			return f
		}
		if usedBefore[b.Index] {
			return RejectBlocked
		}
		if b.Index <= start {
			return RejectEarly
		}
		return ""
	}

	for _, s := range spec.Steps {
		start := d
		if spec.Order == OrderPending {
			start = prev
		}
		var eligible []agreementBlock
		if start != infinity {
			for _, b := range later {
				_, scoped := b.Fields["scope"]
				if b.Status == StatusValid && !scoped && b.Fields["method"] != "tsa" && b.Index > start && !used[b.Index] {
					eligible = append(eligible, b)
				}
			}
		}
		out := matchStep(s, eligible, qualifies)
		outcomes = append(outcomes, out)
		done := infinity
		if out.k != 0 {
			done = out.k
			if spec.Order != OrderPending {
				done = max(out.k, prev)
			}
		}
		usedBefore := map[int]bool{}
		for k := range used {
			usedBefore[k] = true
		}
		for _, a := range out.assigned {
			line := s.Lines[a.line]
			res.satisfied = append(res.satisfied, Satisfaction{DeclaredBy: d, Step: s.Step, Line: line.Line, Index: a.block})
			used[a.block] = true
			// SPEC 5.8.6: guide does not report a signer whose edges go only to pattern lines
			if s.Step > 1 && spec.Order != OrderPending && a.block < prev && !(spec.Order == OrderGuide && !out.namedEdge[a.signer]) {
				signer := ""
				for _, b := range later {
					if b.Index == a.block {
						signer = b.Fields["signer"]
						break
					}
				}
				res.violations = append(res.violations, OrderViolation{DeclaredBy: d, Step: s.Step, Line: line.Line, Index: a.block, Method: line.Method, Signer: signer, Order: spec.Order})
			}
		}
		st := DeclarationStep{Step: s.Step, Any: s.Any, Need: out.need, Count: out.size, Complete: out.k != 0, Lines: []StepLine{}}
		if out.k == 0 && firstIncomplete != 0 && spec.Order != OrderGuide {
			st.BlockedBy = firstIncomplete
		}
		for j, l := range s.Lines {
			sl := StepLine{Line: l.Line, Blocks: []int{}}
			for _, a := range out.assigned {
				if a.line == j {
					sl.Blocks = append(sl.Blocks, a.block)
				}
			}
			sort.Ints(sl.Blocks)
			st.Lines = append(st.Lines, sl)
		}
		res.steps = append(res.steps, st)
		if out.k == 0 {
			if firstIncomplete == 0 {
				firstIncomplete = s.Step
			}
			assignedSigners := map[string]bool{}
			filled := map[int]bool{}
			for _, a := range out.assigned {
				assignedSigners[a.signer] = true
				filled[a.line] = true
			}
			for j, l := range s.Lines {
				if filled[j] && lineCap(s, l) != infinity {
					continue
				}
				rejected := []Rejection{}
				for _, b := range later {
					if assignedSigners[idOf(b.Fields)] || !targetMatches(l, b.Fields) {
						continue
					}
					reason := rejectReason(b, l, usedBefore, start)
					if reason == "" {
						continue
					}
					rejected = append(rejected, Rejection{Index: b.Index, Reason: reason})
					if reason == RejectRosterUnavailable {
						addCause("a roster cannot be obtained")
					}
					if reason == RejectUnresolved && isUndeterminedCode(b.Code) {
						if b.Code == KindOffline {
							addCause("offline")
						} else {
							addCause("network failure")
						}
					}
				}
				blockedBy := 0
				if firstIncomplete != s.Step && spec.Order != OrderGuide {
					blockedBy = firstIncomplete
				}
				res.missing = append(res.missing, MissingRequirement{Requirement: l, Need: out.need - out.size, BlockedBy: blockedBy, Rejected: rejected})
			}
		}
		prev = done
	}

	complete := !slices.ContainsFunc(outcomes, func(o stepOutcome) bool { return o.k == 0 })
	switch {
	case spec.Order == OrderStrict && len(res.violations) > 0:
		res.status = AgreementViolated
	case decl.Status == StatusUnresolved && isUndeterminedCode(decl.Code):
		res.status = AgreementUndetermined
		addCause("the declaring block was not checked (" + decl.Code + ")")
	case complete:
		res.status = AgreementComplete
	case len(causes) > 0:
		res.status = AgreementUndetermined
	default:
		res.status = AgreementPending
	}

	if !complete {
		idx := firstIncomplete - 1
		linesOf := func(k int) []Requirement {
			out := []Requirement{}
			for _, m := range res.missing {
				if m.Step == k+1 {
					out = append(out, m.Requirement)
				}
			}
			return out
		}
		left := func(o stepOutcome) int {
			if o.k != 0 {
				return 0
			}
			return o.need - o.size
		}
		n := &NextStep{DeclaredBy: d, Step: idx + 1, Need: left(outcomes[idx]), Candidates: linesOf(idx), Later: []LaterStep{}}
		for j, s := range spec.Steps[idx+1:] {
			n.Later = append(n.Later, LaterStep{Step: s.Step, Need: left(outcomes[idx+1+j]), Lines: linesOf(idx + 1 + j)})
		}
		res.next = n
	}
	if res.status == AgreementUndetermined {
		res.detail = strings.Join(causes, "; ")
	}
	return res
}

var agreementRank = map[string]int{AgreementComplete: 0, AgreementPending: 1, AgreementUndetermined: 2, AgreementUnsupported: 3, AgreementViolated: 4}

// valid and unresolved blocks declare requirements, so an unchecked chain is never complete
func evaluateAgreement(blocks []agreementBlock, oracle membershipOracle) Agreement {
	if oracle == nil {
		oracle = func(string, string) string { return MembershipUnavailable }
	}
	a := emptyAgreement()
	worst := ""
	for _, b := range blocks {
		if (b.Status != StatusValid && b.Status != StatusUnresolved) || b.Fields["require"] == "" {
			continue
		}
		parsed := ParseRequire(b.Fields["require"], b.Index)
		if len(parsed.Errors) > 0 {
			continue
		}
		a.Required = append(a.Required, parsed.Requirements...)
		var status, detail string
		steps := []DeclarationStep{}
		switch {
		case len(parsed.Unsupported) > 0:
			status, detail = AgreementUnsupported, strings.Join(parsed.Unsupported, "; ")
		case parsed.OverLimit != "":
			status, detail = AgreementUndetermined, parsed.OverLimit
		default:
			r := evaluateDeclaration(b, parsed, blocks, oracle)
			status, detail = r.status, r.detail
			if r.steps != nil {
				steps = r.steps
			}
			a.Missing = append(a.Missing, r.missing...)
			a.Violations = append(a.Violations, r.violations...)
			a.Satisfied = append(a.Satisfied, r.satisfied...)
			if r.next != nil {
				a.Next = append(a.Next, *r.next)
			}
		}
		a.Declarations = append(a.Declarations, Declaration{DeclaredBy: b.Index, Order: parsed.Spec.Order, Status: status, Detail: detail, Steps: steps})
		if worst == "" || agreementRank[status] > agreementRank[worst] {
			worst = status
		}
	}
	if worst != "" {
		a.Status = worst
	}
	return a
}

// --- member_of candidates (SPEC 5.8): the (roster, signer) pairs a verifier has to look up

type membershipQuery struct{ roster, id string }

func membershipQueries(blocks []agreementBlock) []membershipQuery {
	var out []membershipQuery
	seen := map[membershipQuery]bool{}
	for _, d := range blocks {
		if (d.Status != StatusValid && d.Status != StatusUnresolved) || d.Fields["require"] == "" {
			continue
		}
		parsed := ParseRequire(d.Fields["require"], d.Index)
		if len(parsed.Errors) > 0 || len(parsed.Unsupported) > 0 || parsed.OverLimit != "" {
			continue
		}
		for _, r := range parsed.Requirements {
			if r.Attributes.MemberOf == "" {
				continue
			}
			for _, b := range blocks {
				if _, scoped := b.Fields["scope"]; b.Index <= d.Index || b.Status != StatusValid || scoped || !targetMatches(r, b.Fields) {
					continue
				}
				q := membershipQuery{r.Attributes.MemberOf, idOf(b.Fields)}
				if !seen[q] {
					seen[q] = true
					out = append(out, q)
				}
			}
		}
	}
	return out
}

func jsNonSpace(s string) bool { return !strings.ContainsFunc(s, isJSSpace) }
