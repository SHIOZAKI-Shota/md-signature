package mdsig

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"regexp"
	"strings"
)

// --- Signed lists (SPEC 5.10): one ```mdsig-list fence in the body of a signed document

const (
	signedListRevocation = "revocation"
	signedListMembers    = "members"
	signedListInfo       = "mdsig-list"
)

var signedListEntryRe = map[string]*regexp.Regexp{
	signedListRevocation: regexp.MustCompile(`^revoked: sha256:([0-9a-f]{64})$`),
	signedListMembers:    regexp.MustCompile(`^member: (\S+)$`),
}

func memberIDOK(id string) bool {
	c := strings.IndexByte(id, ':')
	if c <= 0 {
		return false
	}
	method := id[:c]
	if !methodRe.MatchString(method) || method == "tsa" {
		return false
	}
	return CheckSignerID(method, id[c+1:]) == "" && id[c+1:] != ""
}

// the entries, or why the list cannot be trusted
func parseSignedList(body, listType string) ([]string, string) {
	type fence struct {
		lines  []string
		closed bool
	}
	var fences []*fence
	var current *fence
	for _, l := range linesWithFence(body) {
		if l.IsOpen {
			current = nil
			if l.Info == signedListInfo {
				current = &fence{}
				fences = append(fences, current)
			}
			continue
		}
		if current == nil {
			continue
		}
		if l.Close {
			current.closed = true
			current = nil
			continue
		}
		current.lines = append(current.lines, l.Line)
	}
	if len(fences) != 1 {
		return nil, fmt.Sprintf("expected exactly one ```%s fence, found %d", signedListInfo, len(fences))
	}
	f := fences[0]
	if !f.closed {
		return nil, fmt.Sprintf("the %s fence is not closed", signedListInfo)
	}
	if len(f.lines) == 0 || f.lines[0] != "type: "+listType {
		return nil, fmt.Sprintf("the list is not %q", "type: "+listType)
	}
	entries := []string{}
	re := signedListEntryRe[listType]
	for i, line := range f.lines[1:] {
		m := re.FindStringSubmatch(line)
		if m == nil || !jsNonSpace(m[1]) || (listType == signedListMembers && !memberIDOK(m[1])) {
			return nil, fmt.Sprintf("line %d of the list is not a valid entry: %s", i+2, jsonString(line))
		}
		entries = append(entries, m[1])
	}
	return entries, ""
}

// --- DNS rosters (SPEC 5.8): <label>._member._mdsig.<domain> TXT "v=mdsig1; m=<method:signer>"

const memberLabelPrefix = "md-signature/member/v1"

var base32LowerNoPad = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func MemberRecordName(id, domain string) (string, error) {
	if !isLdhDomain(domain) {
		return "", fmt.Errorf("%q is not a lower-case domain name", domain)
	}
	sum := sha256.Sum256([]byte(memberLabelPrefix + "\n" + id))
	return base32LowerNoPad.EncodeToString(sum[:]) + "._member._mdsig." + domain, nil
}

func MemberRecordValue(id string) string { return "v=mdsig1; m=" + id }

// NXDOMAIN, NODATA and records for another m are "not-member"; any other failure is "unavailable"
func lookupDNSMember(ctx context.Context, id, domain string, o *ResolveOptions) string {
	if o.Offline {
		return MembershipUnavailable
	}
	name, err := MemberRecordName(id, domain)
	if err != nil {
		return MembershipUnavailable
	}
	records, err := lookupTXT(ctx, name, o)
	if err != nil {
		return MembershipUnavailable
	}
	// security: m must name the signer, so wildcard records and synthesized answers never make a member
	for _, r := range records {
		t := parseDNSTags(r)
		if t["v"] == "mdsig1" && t["m"] == id {
			return MembershipMember
		}
	}
	return MembershipNotMember
}

func CheckMemberRecord(ctx context.Context, id, domain string, o *ResolveOptions) string {
	if o == nil {
		o = &ResolveOptions{}
	}
	return lookupDNSMember(ctx, id, domain, o)
}

// SPEC 5.10: an empty body gets a list under title; a body whose list does not follow the format is an error
func AddToRevocationList(body, title string, ids []string) (string, int, error) {
	if strings.TrimSpace(body) == "" {
		body = title + "\n\n```" + signedListInfo + "\ntype: " + signedListRevocation + "\n```\n"
	}
	entries, e := parseSignedList(body, signedListRevocation)
	if e != "" {
		return "", 0, fmt.Errorf("%s", e)
	}
	present := map[string]bool{}
	for _, x := range entries {
		present[x] = true
	}
	var add []string
	for _, id := range ids {
		if !present[id] {
			present[id] = true
			add = append(add, "revoked: sha256:"+id+"\n")
		}
	}
	inList := false
	for _, l := range linesWithFence(body) {
		if l.IsOpen {
			inList = l.Info == signedListInfo
			continue
		}
		if inList && l.Close {
			return body[:l.Offset] + strings.Join(add, "") + body[l.Offset:], len(add), nil
		}
	}
	return "", 0, fmt.Errorf("the %s fence is not closed", signedListInfo)
}
