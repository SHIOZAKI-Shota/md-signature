package mdsig

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// --- JSON schema (CLI_SPEC 5): the shape `mdsig verify --json` prints per file, without "file"

type JSONTSA struct {
	Status   string  `json:"status"`
	Verified bool    `json:"verified"`
	Signer   *string `json:"signer"`
	GenTime  *string `json:"gen_time"`
	Detail   string  `json:"detail"`
}

// JSONSignatureTSA adds T(k) and the tsa block it comes from (SPEC 4.6)
type JSONSignatureTSA struct {
	JSONTSA
	Time  *string `json:"time"`
	Block *int    `json:"block"`
}

type JSONPartial struct {
	Sections []string `json:"sections"`
}

type JSONWebAuthn struct {
	RPID           string `json:"rp_id"`
	Origin         string `json:"origin"`
	UserVerified   bool   `json:"user_verified"`
	BackupEligible bool   `json:"backup_eligible"`
	BackedUp       bool   `json:"backed_up"`
}

type JSONPGP struct {
	Fpr       string  `json:"fpr"`
	UID       *string `json:"uid"`
	KeyAlg    *string `json:"key_alg"`
	KeySource *string `json:"key_source"`
	Created   *string `json:"created"`
}

type JSONResource struct {
	Ref    string  `json:"ref"`
	Status string  `json:"status"`
	Detail *string `json:"detail"`
}

type JSONRevocation struct {
	Status string  `json:"status"`
	Detail *string `json:"detail"`
}

type JSONTofu struct {
	Status      string `json:"status"`
	Fingerprint string `json:"fingerprint"`
}

type JSONSignature struct {
	Index       int               `json:"index"`
	Line        int               `json:"line"`
	Status      string            `json:"status"`
	Code        *string           `json:"code"`
	Message     *string           `json:"message"`
	Fields      map[string]string `json:"fields"`
	DisplayName *string           `json:"display_name"`
	HashOK      *bool             `json:"hash_ok"`
	Partial     *JSONPartial      `json:"partial"`
	KeySource   *string           `json:"key_source"`
	Tofu        *JSONTofu         `json:"tofu"`
	WebAuthn    *JSONWebAuthn     `json:"webauthn"`
	PGP         *JSONPGP          `json:"pgp"`
	Resources   []JSONResource    `json:"resources"`
	Revocation  *JSONRevocation   `json:"revocation"`
	TSA         *JSONSignatureTSA `json:"tsa"`
	Warnings    []string          `json:"warnings"`
}

// JSONAttributes are the attributes of a requirement line, written in the order the TS core writes them
type JSONAttributes RequirementAttributes

func (a JSONAttributes) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	add := func(k string, v any) {
		if b.Len() > 1 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(v)
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	if a.Role != "" {
		add("role", a.Role)
	}
	if a.Pubkey != "" {
		add("pubkey", a.Pubkey)
	}
	if a.UserVerified {
		add("user_verified", true)
	}
	if a.MemberOf != "" {
		add("member_of", a.MemberOf)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func (a *JSONAttributes) UnmarshalJSON(data []byte) error {
	var m struct {
		Role         string `json:"role"`
		UserVerified bool   `json:"user_verified"`
		MemberOf     string `json:"member_of"`
		Pubkey       string `json:"pubkey"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*a = JSONAttributes{Role: m.Role, UserVerified: m.UserVerified, MemberOf: m.MemberOf, Pubkey: m.Pubkey}
	return nil
}

type JSONRequirement struct {
	DeclaredBy int            `json:"declared_by"`
	Step       int            `json:"step"`
	Any        *int           `json:"any"`
	Line       int            `json:"line"`
	Method     string         `json:"method"`
	Signer     string         `json:"signer"`
	Pattern    bool           `json:"pattern"`
	Attributes JSONAttributes `json:"attributes"`
}

type JSONRejection struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

type JSONMissingRequirement struct {
	JSONRequirement
	Need      int             `json:"need"`
	BlockedBy int             `json:"blocked_by,omitempty"`
	Rejected  []JSONRejection `json:"rejected"`
}

type JSONOrderViolation struct {
	DeclaredBy int    `json:"declared_by"`
	Step       int    `json:"step"`
	Line       int    `json:"line"`
	Index      int    `json:"index"`
	Method     string `json:"method"`
	Signer     string `json:"signer"`
	Order      string `json:"order"`
}

type JSONLaterStep struct {
	Step  int               `json:"step"`
	Need  int               `json:"need"`
	Lines []JSONRequirement `json:"lines"`
}

type JSONNext struct {
	DeclaredBy int               `json:"declared_by"`
	Step       int               `json:"step"`
	Need       int               `json:"need"`
	Candidates []JSONRequirement `json:"candidates"`
	Later      []JSONLaterStep   `json:"later"`
}

type JSONSatisfaction struct {
	DeclaredBy int `json:"declared_by"`
	Step       int `json:"step"`
	Line       int `json:"line"`
	Index      int `json:"index"`
}

type JSONDeclaration struct {
	DeclaredBy int     `json:"declared_by"`
	Order      string  `json:"order"`
	Status     string  `json:"status"`
	Detail     *string `json:"detail"`
}

type JSONAgreement struct {
	Status       string                   `json:"status"`
	Required     []JSONRequirement        `json:"required"`
	Missing      []JSONMissingRequirement `json:"missing"`
	Violations   []JSONOrderViolation     `json:"violations"`
	Next         []JSONNext               `json:"next"`
	Satisfied    []JSONSatisfaction       `json:"satisfied"`
	Declarations []JSONDeclaration        `json:"declarations"`
}

// JSONResult is the result of one document in the shape of CLI_SPEC 5 (`verify --json`, without "file")
type JSONResult struct {
	OK         bool            `json:"ok"`
	Error      *string         `json:"error"`
	Warnings   []string        `json:"warnings"`
	Agreement  JSONAgreement   `json:"agreement"`
	Signatures []JSONSignature `json:"signatures"`
}

func toJSONRequirement(r Requirement) JSONRequirement {
	j := JSONRequirement{DeclaredBy: r.DeclaredBy, Step: r.Step, Line: r.Line, Method: r.Method, Signer: r.Signer, Pattern: r.Pattern, Attributes: JSONAttributes(r.Attributes)}
	if r.Any != 0 {
		n := r.Any
		j.Any = &n
	}
	return j
}

func toJSONRequirements(rs []Requirement) []JSONRequirement {
	out := []JSONRequirement{}
	for _, r := range rs {
		out = append(out, toJSONRequirement(r))
	}
	return out
}

func toJSONAgreement(a Agreement) JSONAgreement {
	out := JSONAgreement{Status: a.Status, Required: toJSONRequirements(a.Required), Missing: []JSONMissingRequirement{}, Violations: []JSONOrderViolation{},
		Next: []JSONNext{}, Satisfied: []JSONSatisfaction{}, Declarations: []JSONDeclaration{}}
	if out.Status == "" {
		out.Status = AgreementNone
	}
	for _, m := range a.Missing {
		jm := JSONMissingRequirement{JSONRequirement: toJSONRequirement(m.Requirement), Need: m.Need, BlockedBy: m.BlockedBy, Rejected: []JSONRejection{}}
		for _, x := range m.Rejected {
			jm.Rejected = append(jm.Rejected, JSONRejection{Index: x.Index, Reason: x.Reason})
		}
		out.Missing = append(out.Missing, jm)
	}
	for _, v := range a.Violations {
		out.Violations = append(out.Violations, JSONOrderViolation{DeclaredBy: v.DeclaredBy, Step: v.Step, Line: v.Line, Index: v.Index, Method: v.Method, Signer: v.Signer, Order: v.Order})
	}
	for _, n := range a.Next {
		jn := JSONNext{DeclaredBy: n.DeclaredBy, Step: n.Step, Need: n.Need, Candidates: toJSONRequirements(n.Candidates), Later: []JSONLaterStep{}}
		for _, l := range n.Later {
			jn.Later = append(jn.Later, JSONLaterStep{Step: l.Step, Need: l.Need, Lines: toJSONRequirements(l.Lines)})
		}
		out.Next = append(out.Next, jn)
	}
	for _, s := range a.Satisfied {
		out.Satisfied = append(out.Satisfied, JSONSatisfaction{DeclaredBy: s.DeclaredBy, Step: s.Step, Line: s.Line, Index: s.Index})
	}
	for _, d := range a.Declarations {
		out.Declarations = append(out.Declarations, JSONDeclaration{DeclaredBy: d.DeclaredBy, Order: d.Order, Status: d.Status, Detail: strPtr(d.Detail)})
	}
	return out
}

func tsaOf(s *BlockResult) *JSONSignatureTSA {
	t := s.Time
	if s.TSA != nil {
		j := &JSONSignatureTSA{JSONTSA: ToJSONTSA(*s.TSA)}
		if t != nil {
			j.Time, j.Block = &t.At, &t.Block
		}
		return j
	}
	// SPEC 4.6: a signature block reports T(k) from the tsa blocks after it
	if t == nil {
		return nil
	}
	gen := t.GenTime
	return &JSONSignatureTSA{
		JSONTSA: JSONTSA{Status: TSAOK, Verified: true, Signer: strPtr(t.Signer), GenTime: &gen, Detail: "covered by tsa block #" + strconv.Itoa(t.Block)},
		Time:    &t.At, Block: &t.Block,
	}
}

func toJSONSignature(s *BlockResult) JSONSignature {
	js := JSONSignature{
		Index: s.Index, Line: s.Line, Status: s.Status, Code: strPtr(s.Code), Message: strPtr(s.Message),
		Fields: s.Fields, DisplayName: strPtr(s.Fields["display_name"]), HashOK: s.HashOk, KeySource: strPtr(s.KeySource), Warnings: s.Warnings, TSA: tsaOf(s),
	}
	if js.Fields == nil {
		js.Fields = map[string]string{}
	}
	if s.Tofu != nil {
		js.Tofu = &JSONTofu{Status: s.Tofu.Status, Fingerprint: s.Tofu.Fingerprint}
	}
	if js.Warnings == nil {
		js.Warnings = []string{}
	}
	if s.Partial != nil {
		js.Partial = &JSONPartial{Sections: s.Partial}
	}
	if w := s.WebAuthn; w != nil {
		js.WebAuthn = &JSONWebAuthn{RPID: w.RPID, Origin: w.Origin, UserVerified: w.UserVerified, BackupEligible: w.BackupEligible, BackedUp: w.BackedUp}
	}
	if s.PGP != nil {
		js.PGP = &JSONPGP{Fpr: s.PGP.Fpr, UID: strPtr(s.PGP.UID), KeyAlg: strPtr(s.PGP.KeyAlg), KeySource: strPtr(s.PGP.KeySource), Created: strPtr(s.PGP.Created)}
	}
	if s.Resources != nil {
		js.Resources = []JSONResource{}
		for _, r := range s.Resources {
			js.Resources = append(js.Resources, JSONResource{Ref: r.Ref, Status: r.Status, Detail: strPtr(r.Detail)})
		}
	}
	if s.Revocation != nil {
		js.Revocation = &JSONRevocation{Status: s.Revocation.Status, Detail: strPtr(s.Revocation.Detail)}
	}
	return js
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ToJSONTSA converts a timestamp check to its JSON form
func ToJSONTSA(c TSACheck) JSONTSA {
	return JSONTSA{Status: c.Status, Verified: c.Verified, Signer: strPtr(c.Signer), GenTime: strPtr(c.GenTime), Detail: c.Detail}
}

// nil gives the empty result for a file that could not be read; OK follows CLI_SPEC 4
func ToJSON(r *VerifyResult) JSONResult {
	out := JSONResult{Warnings: []string{}, Signatures: []JSONSignature{}, Agreement: toJSONAgreement(emptyAgreement())}
	if r == nil {
		return out
	}
	out.OK = agreementOK(r)
	out.Error = strPtr(r.Error)
	out.Agreement = toJSONAgreement(r.Agreement)
	out.Warnings = append(out.Warnings, r.Warnings...)
	for _, s := range r.Signatures {
		out.Signatures = append(out.Signatures, toJSONSignature(s))
	}
	return out
}
