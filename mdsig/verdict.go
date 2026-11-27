package mdsig

// --- document verdict (CLI_SPEC 4)

const (
	VerdictValid        = "valid"
	VerdictPending      = "pending"
	VerdictUndetermined = "undetermined"
	VerdictUnresolved   = "unresolved"
	VerdictOffline      = "offline"
	VerdictViolated     = "violated"
	VerdictUnsupported  = "unsupported"
	VerdictFailed       = "failed"
	VerdictBroken       = "broken"
	VerdictUnsigned     = "unsigned"
)

type Verdict struct {
	Kind     string
	ExitCode int
}

func DocumentVerdict(r *VerifyResult) Verdict {
	if r.Error != "" {
		// "no signatures found" is the error VerifyDocument gives for a document without a chain
		if r.Error == "no signatures found" {
			return Verdict{VerdictUnsigned, 1}
		}
		return Verdict{VerdictBroken, 1}
	}
	offline, unresolved := true, false
	for _, s := range r.Signatures {
		switch s.Status {
		case StatusValid:
		case StatusUnresolved:
			unresolved = true
			if s.Code != KindOffline {
				offline = false
			}
		default:
			return Verdict{VerdictFailed, 1}
		}
	}
	// CLI_SPEC 4: violated and unsupported fail; undetermined is like an unchecked block; pending is not a failure
	switch r.Agreement.Status {
	case AgreementViolated:
		return Verdict{VerdictViolated, 1}
	case AgreementUnsupported:
		return Verdict{VerdictUnsupported, 1}
	}
	if unresolved {
		if offline {
			return Verdict{VerdictOffline, 3}
		}
		return Verdict{VerdictUnresolved, 3}
	}
	switch r.Agreement.Status {
	case AgreementUndetermined:
		return Verdict{VerdictUndetermined, 3}
	case AgreementPending:
		return Verdict{VerdictPending, 5}
	}
	return Verdict{VerdictValid, 0}
}
