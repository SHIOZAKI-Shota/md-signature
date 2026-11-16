package mdsig

import (
	"fmt"
	"regexp"
	"strings"
)

type Requirement struct {
	Method     string
	Signer     string
	Role       string
	DeclaredBy int
}

func (r Requirement) String() string {
	s := r.Method + ":" + r.Signer
	if r.Role != "" {
		s += " " + r.Role
	}
	return s
}

const (
	AgreementNone     = "none"
	AgreementComplete = "complete"
	AgreementPending  = "pending"
)

type Agreement struct {
	Status   string
	Required []Requirement
	Missing  []Requirement
}

var requireLineRe = regexp.MustCompile(`^([a-z][a-z0-9-]*):(\S+)(?: (\S+))?$`)

func ParseRequire(value string, declaredBy int) ([]Requirement, []string) {
	var reqs []Requirement
	var errs []string
	for _, line := range strings.Split(value, "\n") {
		m := requireLineRe.FindStringSubmatch(line)
		if m == nil || !jsNonSpace(m[2]) || (m[3] != "" && !jsNonSpace(m[3])) {
			errs = append(errs, fmt.Sprintf("require: expected \"<method>:<signer> [role]\", got %s", jsonString(line)))
			continue
		}
		reqs = append(reqs, Requirement{Method: m[1], Signer: m[2], Role: m[3], DeclaredBy: declaredBy})
	}
	return reqs, errs
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

// SPEC 5.8: unresolved blocks still declare requirements but only valid blocks satisfy them
func evaluateAgreement(blocks []agreementBlock) Agreement {
	required := []Requirement{}
	for _, b := range blocks {
		if !b.Declares || b.Fields["require"] == "" {
			continue
		}
		reqs, _ := ParseRequire(b.Fields["require"], b.Index)
		required = append(required, reqs...)
	}
	if len(required) == 0 {
		return Agreement{Status: AgreementNone, Required: required, Missing: []Requirement{}}
	}
	missing := []Requirement{}
	for _, r := range required {
		satisfied := false
		for _, b := range blocks {
			// SPEC 5.8: a block with scope does not cover the declaring block, so it never satisfies
			if _, scoped := b.Fields["scope"]; !scoped && b.Valid && b.Index > r.DeclaredBy && b.Fields["method"] == r.Method && sameSigner(r.Method, b.Fields["signer"], r.Signer) && (r.Role == "" || b.Fields["role"] == r.Role) {
				satisfied = true
				break
			}
		}
		if !satisfied {
			missing = append(missing, r)
		}
	}
	status := AgreementComplete
	if len(missing) > 0 {
		status = AgreementPending
	}
	return Agreement{Status: status, Required: required, Missing: missing}
}
