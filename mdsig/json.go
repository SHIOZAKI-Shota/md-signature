package mdsig

// --- JSON schema (CLI_SPEC 5)

type JSONTSA struct {
	Status   string  `json:"status"`
	Verified bool    `json:"verified"`
	Signer   *string `json:"signer"`
	GenTime  *string `json:"gen_time"`
	Detail   string  `json:"detail"`
}

type JSONPartial struct {
	Sections []string `json:"sections"`
}

type JSONWebAuthn struct {
	RPID         string `json:"rp_id"`
	Origin       string `json:"origin"`
	UserVerified bool   `json:"user_verified"`
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

type JSONSignature struct {
	Index      int               `json:"index"`
	Line       int               `json:"line"`
	Status     string            `json:"status"`
	Code       *string           `json:"code"`
	Message    *string           `json:"message"`
	Fields     map[string]string `json:"fields"`
	HashOK     *bool             `json:"hash_ok"`
	Partial    *JSONPartial      `json:"partial"`
	KeySource  *string           `json:"key_source"`
	Tofu       *JSONTofu         `json:"tofu"`
	WebAuthn   *JSONWebAuthn     `json:"webauthn"`
	PGP        *JSONPGP          `json:"pgp"`
	Resources  []JSONResource    `json:"resources"`
	Revocation *JSONRevocation   `json:"revocation"`
	TSA        *JSONTSA          `json:"tsa"`
	Warnings   []string          `json:"warnings"`
}

type JSONTofu struct {
	Status      string `json:"status"`
	Fingerprint string `json:"fingerprint"`
}

type JSONRequirement struct {
	Method     string `json:"method"`
	Signer     string `json:"signer"`
	Role       string `json:"role,omitempty"`
	DeclaredBy int    `json:"declared_by"`
	Step       int    `json:"step"`
	Any        int    `json:"any"`
}

type JSONMissingRequirement struct {
	JSONRequirement
	Need      int  `json:"need"`
	BlockedBy int  `json:"blocked_by,omitempty"`
	Early     bool `json:"early,omitempty"`
}

type JSONOrderViolation struct {
	DeclaredBy int    `json:"declared_by"`
	Step       int    `json:"step"`
	Index      int    `json:"index"`
	Method     string `json:"method"`
	Signer     string `json:"signer"`
	Role       string `json:"role,omitempty"`
	Order      string `json:"order"`
}

type JSONAgreement struct {
	Status     string                   `json:"status"`
	Required   []JSONRequirement        `json:"required"`
	Missing    []JSONMissingRequirement `json:"missing"`
	Violations []JSONOrderViolation     `json:"violations"`
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
	return JSONRequirement{Method: r.Method, Signer: r.Signer, Role: r.Role, DeclaredBy: r.DeclaredBy, Step: r.Step, Any: r.Any}
}

func toJSONAgreement(a Agreement) JSONAgreement {
	out := JSONAgreement{Status: a.Status, Required: []JSONRequirement{}, Missing: []JSONMissingRequirement{}, Violations: []JSONOrderViolation{}}
	if out.Status == "" {
		out.Status = AgreementNone
	}
	for _, r := range a.Required {
		out.Required = append(out.Required, toJSONRequirement(r))
	}
	for _, m := range a.Missing {
		out.Missing = append(out.Missing, JSONMissingRequirement{JSONRequirement: toJSONRequirement(m.Requirement), Need: m.Need, BlockedBy: m.BlockedBy, Early: m.Early})
	}
	for _, v := range a.Violations {
		out.Violations = append(out.Violations, JSONOrderViolation{DeclaredBy: v.DeclaredBy, Step: v.Step, Index: v.Index, Method: v.Method, Signer: v.Signer, Role: v.Role, Order: v.Order})
	}
	return out
}

func toJSONSignature(s *BlockResult) JSONSignature {
	js := JSONSignature{
		Index: s.Index, Line: s.Line, Status: s.Status, Code: strPtr(s.Code), Message: strPtr(s.Message),
		Fields: s.Fields, HashOK: s.HashOk, KeySource: strPtr(s.KeySource), Warnings: s.Warnings,
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
	if s.TSA != nil {
		t := ToJSONTSA(*s.TSA)
		js.TSA = &t
	}
	if s.Partial != nil {
		js.Partial = &JSONPartial{Sections: s.Partial}
	}
	if s.WebAuthn != nil {
		js.WebAuthn = &JSONWebAuthn{RPID: s.WebAuthn.RPID, Origin: s.WebAuthn.Origin, UserVerified: s.WebAuthn.UserVerified}
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

// ToJSON converts a verification result; nil gives the empty result used for a file that could not be read.
// OK is true when there is no error, every signature is valid and the agreement is not violated (a pending agreement is still OK, CLI_SPEC 4).
func ToJSON(r *VerifyResult) JSONResult {
	out := JSONResult{Warnings: []string{}, Signatures: []JSONSignature{}, Agreement: toJSONAgreement(Agreement{})}
	if r == nil {
		return out
	}
	out.OK = r.Error == "" && r.Agreement.Status != AgreementViolated
	out.Error = strPtr(r.Error)
	out.Agreement = toJSONAgreement(r.Agreement)
	out.Warnings = append(out.Warnings, r.Warnings...)
	for _, s := range r.Signatures {
		out.OK = out.OK && s.Status == StatusValid
		out.Signatures = append(out.Signatures, toJSONSignature(s))
	}
	return out
}
