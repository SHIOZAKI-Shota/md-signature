package mdsig

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type Requirement struct {
	Method     string
	Signer     string
	Role       string
	DeclaredBy int
	// SPEC 5.8: 1 when the value has no step lines
	Step int
	// how many members of the step must sign
	Any int
}

func (r Requirement) String() string {
	s := r.Method + ":" + r.Signer
	if r.Role != "" {
		s += " " + r.Role
	}
	return s
}

type MissingRequirement struct {
	Requirement
	// signatures still needed in this step
	Need int
	// an earlier step that has to complete first; 0 when none
	BlockedBy int
	// this signer signed before the previous step was complete, so that signature does not count
	Early bool
}

type OrderViolation struct {
	DeclaredBy int
	Step       int
	Index      int
	Method     string
	Signer     string
	Role       string
	Order      string
}

const (
	AgreementNone     = "none"
	AgreementComplete = "complete"
	AgreementPending  = "pending"
	AgreementViolated = "violated"

	OrderPending = "pending"
	OrderGuide   = "guide"
	OrderStrict  = "strict"
)

type Agreement struct {
	Status     string
	Required   []Requirement
	Missing    []MissingRequirement
	Violations []OrderViolation
}

type RequireStep struct {
	Step    int
	Any     int
	Members []Requirement
}

type RequireSpec struct {
	Order string
	Steps []RequireStep
	// format 0.0.1 keeps its rules: duplicates allowed, one signature may satisfy several lines
	Legacy bool
}

// Requirements lists every member of every step in order.
func (s RequireSpec) Requirements() []Requirement {
	out := []Requirement{}
	for _, st := range s.Steps {
		out = append(out, st.Members...)
	}
	return out
}

var (
	requireLineRe  = regexp.MustCompile(`^([a-z][a-z0-9-]*):(\S+)(?: (\S+))?$`)
	requireOrderRe = regexp.MustCompile(`^order (pending|guide|strict)$`)
	requireStepRe  = regexp.MustCompile(`^step ([1-9][0-9]{0,3})(?: any ([1-9][0-9]{0,3}))?$`)
	requireKeyword = regexp.MustCompile(`^(order|step)( |$)`)
)

// SPEC 5.8: step and order lines exist from format 0.0.2 on
const stepsSince = "0.0.2"

func sameRequirement(a, b Requirement) bool {
	return a.Method == b.Method && sameSigner(a.Method, a.Signer, b.Signer) && a.Role == b.Role
}

// ParseRequire reads a require value written by a block of the given format version ("" means the current one).
func ParseRequire(value string, declaredBy int, version string) (RequireSpec, []string) {
	var errs []string
	allowSteps := version != "0.0.1"
	spec := RequireSpec{Order: OrderPending, Legacy: !allowSteps}
	var implicit *RequireStep
	for i, line := range strings.Split(value, "\n") {
		o := requireOrderRe.FindStringSubmatch(line)
		s := requireStepRe.FindStringSubmatch(line)
		if o != nil || s != nil || requireKeyword.MatchString(line) {
			if !allowSteps {
				errs = append(errs, fmt.Sprintf("require: \"step\" and \"order\" lines need format %s, got %s", stepsSince, jsonString(line)))
				continue
			}
			if o != nil {
				if i != 0 {
					errs = append(errs, `require: "order" must be the first line`)
				} else {
					spec.Order = o[1]
				}
				continue
			}
			if s == nil {
				errs = append(errs, fmt.Sprintf("require: expected \"order pending|guide|strict\" or \"step <n> [any <m>]\", got %s", jsonString(line)))
				continue
			}
			if implicit != nil {
				errs = append(errs, `require: "step" lines must come before every requirement`)
				continue
			}
			n, _ := strconv.Atoi(s[1])
			if n != len(spec.Steps)+1 {
				errs = append(errs, fmt.Sprintf("require: expected \"step %d\", got %s", len(spec.Steps)+1, jsonString(line)))
				continue
			}
			anyN := 0
			if s[2] != "" {
				anyN, _ = strconv.Atoi(s[2])
			}
			spec.Steps = append(spec.Steps, RequireStep{Step: n, Any: anyN})
			continue
		}
		m := requireLineRe.FindStringSubmatch(line)
		if m == nil || !jsNonSpace(m[2]) || (m[3] != "" && !jsNonSpace(m[3])) {
			errs = append(errs, fmt.Sprintf("require: expected \"<method>:<signer> [role]\", got %s", jsonString(line)))
			continue
		}
		var target *RequireStep
		if len(spec.Steps) > 0 {
			target = &spec.Steps[len(spec.Steps)-1]
		} else {
			if implicit == nil {
				implicit = &RequireStep{Step: 1}
			}
			target = implicit
		}
		if allowSteps && m[1] == "tsa" {
			errs = append(errs, fmt.Sprintf("require: a tsa block cannot be required, got %s", jsonString(line)))
			continue
		}
		r := Requirement{Method: m[1], Signer: m[2], Role: m[3], DeclaredBy: declaredBy, Step: target.Step}
		if allowSteps && slices.ContainsFunc(target.Members, func(x Requirement) bool { return sameRequirement(x, r) }) {
			errs = append(errs, fmt.Sprintf("require: %s appears twice in step %d", r, target.Step))
			continue
		}
		target.Members = append(target.Members, r)
	}
	if implicit != nil {
		spec.Steps = append(spec.Steps, *implicit)
	}
	for i := range spec.Steps {
		st := &spec.Steps[i]
		if len(st.Members) == 0 {
			errs = append(errs, fmt.Sprintf("require: step %d has no requirement", st.Step))
		}
		if st.Any == 0 {
			st.Any = len(st.Members)
		} else if st.Any > len(st.Members) {
			errs = append(errs, fmt.Sprintf("require: step %d asks for any %d of %d", st.Step, st.Any, len(st.Members)))
		}
		for j := range st.Members {
			st.Members[j].Any = st.Any
		}
	}
	return spec, errs
}

// ECMAScript \S; Go regexp \S is ASCII-only
func jsNonSpace(s string) bool { return !strings.ContainsFunc(s, isJSSpace) }

// SPEC 5.8/5.9: dns signers compare case-insensitively, ignoring a trailing dot
func sameSigner(method, a, b string) bool {
	if method == "dns" {
		return strings.TrimSuffix(strings.ToLower(a), ".") == strings.TrimSuffix(strings.ToLower(b), ".")
	}
	return a == b
}

type agreementBlock struct {
	Index    int
	Valid    bool
	Declares bool
	Fields   map[string]string
}

func requirementMatches(r Requirement, b agreementBlock) bool {
	return b.Fields["method"] == r.Method && sameSigner(r.Method, b.Fields["signer"], r.Signer) && (r.Role == "" || b.Fields["role"] == r.Role)
}

func evaluateDeclaration(declarer int, spec RequireSpec, blocks []agreementBlock) (string, []MissingRequirement, []OrderViolation) {
	var later []agreementBlock
	for _, b := range blocks {
		// SPEC 5.8: a block with scope does not cover the declaring block, and a tsa block has no signer, so neither satisfies
		if _, scoped := b.Fields["scope"]; !scoped && b.Valid && b.Fields["method"] != "tsa" && b.Index > declarer {
			later = append(later, b)
		}
	}
	slices.SortFunc(later, func(a, b agreementBlock) int { return a.Index - b.Index })
	missing := []MissingRequirement{}
	violations := []OrderViolation{}
	if spec.Legacy {
		for _, r := range spec.Steps[0].Members {
			if !slices.ContainsFunc(later, func(b agreementBlock) bool { return requirementMatches(r, b) }) {
				missing = append(missing, MissingRequirement{Requirement: r, Need: 1})
			}
		}
		if len(missing) > 0 {
			return AgreementPending, missing, violations
		}
		return AgreementComplete, missing, violations
	}
	used := map[int]bool{}
	ordered := spec.Order == OrderPending
	// completion position of the previous step; -1 when it is not complete
	prevDone := declarer
	firstIncomplete := 0
	for _, s := range spec.Steps {
		inOrder := func(b agreementBlock) bool { return prevDone >= 0 && b.Index > prevDone }
		matchesStep := func(b agreementBlock) bool {
			return slices.ContainsFunc(s.Members, func(r Requirement) bool { return requirementMatches(r, b) })
		}
		var early []agreementBlock
		for _, b := range later {
			if !used[b.Index] && !inOrder(b) && matchesStep(b) {
				early = append(early, b)
			}
		}
		if s.Step > 1 && spec.Order != OrderPending {
			for _, b := range early {
				i := slices.IndexFunc(s.Members, func(r Requirement) bool { return requirementMatches(r, b) })
				r := s.Members[i]
				violations = append(violations, OrderViolation{DeclaredBy: declarer, Step: s.Step, Index: b.Index, Method: r.Method, Signer: r.Signer, Role: r.Role, Order: spec.Order})
			}
		}
		done := make([]bool, len(s.Members))
		count := 0
		completedAt := -1
		for _, b := range later {
			if count == s.Any {
				break
			}
			if used[b.Index] || (ordered && !inOrder(b)) {
				continue
			}
			j := -1
			for k, r := range s.Members {
				if !done[k] && requirementMatches(r, b) {
					j = k
					break
				}
			}
			if j < 0 {
				continue
			}
			done[j] = true
			count++
			used[b.Index] = true
			if count == s.Any {
				completedAt = b.Index
			}
		}
		if completedAt < 0 {
			if firstIncomplete == 0 {
				firstIncomplete = s.Step
			}
			blockedBy := 0
			if firstIncomplete != s.Step && spec.Order != OrderGuide {
				blockedBy = firstIncomplete
			}
			for k, r := range s.Members {
				if done[k] {
					continue
				}
				signedEarly := s.Step > 1 && slices.ContainsFunc(early, func(b agreementBlock) bool { return requirementMatches(r, b) })
				missing = append(missing, MissingRequirement{Requirement: r, Need: s.Any - count, BlockedBy: blockedBy, Early: signedEarly})
			}
		}
		switch {
		case completedAt >= 0 && (prevDone >= 0 || !ordered):
			prevDone = max(completedAt, prevDone)
		default:
			prevDone = -1
		}
	}
	switch {
	case spec.Order == OrderStrict && len(violations) > 0:
		return AgreementViolated, missing, violations
	case len(missing) > 0:
		return AgreementPending, missing, violations
	}
	return AgreementComplete, missing, violations
}

// SPEC 5.8: unresolved blocks still declare requirements but only valid blocks satisfy them
func evaluateAgreement(blocks []agreementBlock) Agreement {
	a := Agreement{Required: []Requirement{}, Missing: []MissingRequirement{}, Violations: []OrderViolation{}}
	violated := false
	for _, b := range blocks {
		if !b.Declares || b.Fields["require"] == "" {
			continue
		}
		spec, errs := ParseRequire(b.Fields["require"], b.Index, b.Fields["v"])
		if len(errs) > 0 {
			continue
		}
		a.Required = append(a.Required, spec.Requirements()...)
		status, missing, violations := evaluateDeclaration(b.Index, spec, blocks)
		a.Missing = append(a.Missing, missing...)
		a.Violations = append(a.Violations, violations...)
		violated = violated || status == AgreementViolated
	}
	switch {
	case len(a.Required) == 0:
		a.Status = AgreementNone
		a.Missing = []MissingRequirement{}
		a.Violations = []OrderViolation{}
	case violated:
		a.Status = AgreementViolated
	case len(a.Missing) > 0:
		a.Status = AgreementPending
	default:
		a.Status = AgreementComplete
	}
	return a
}
