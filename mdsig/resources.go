package mdsig

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	ResourceOK          = "ok"
	ResourceMismatch    = "mismatch"
	ResourceMissing     = "missing"
	ResourceUnreachable = "unreachable"
	ResourceNotChecked  = "not-checked"
)

type resourceEntry struct {
	Hash   string
	Ref    string
	Remote bool
}

type ResourceResult struct {
	Ref    string
	Status string
	Detail string
}

type ResourceItem struct {
	Ref   string
	Bytes []byte
}

var (
	resourceLineRe = regexp.MustCompile(`^sha256:([0-9a-f]{64}) (.+)$`)
	schemeRe       = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*:`)
	httpsPrefixRe  = regexp.MustCompile(`(?i)^https://`)
)

func isHTTPSRef(ref string) bool {
	if !httpsPrefixRe.MatchString(ref) || len(ref) <= len("https://") {
		return false
	}
	c := []rune(ref[len("https://"):])[0]
	return c != '/' && !isJSSpace(c)
}

func ValidateResourceRef(ref string) string {
	if isHTTPSRef(ref) {
		return ""
	}
	if schemeRe.MatchString(ref) {
		return fmt.Sprintf("%s: only https:// URLs and relative paths are allowed", jsonString(ref))
	}
	if strings.HasPrefix(ref, "/") {
		return fmt.Sprintf("%s: absolute paths are not allowed", jsonString(ref))
	}
	if strings.Contains(ref, `\`) {
		return fmt.Sprintf("%s: use \"/\" as the path separator", jsonString(ref))
	}
	for _, seg := range strings.Split(ref, "/") {
		if seg == ".." {
			return fmt.Sprintf("%s: \"..\" is not allowed", jsonString(ref))
		}
	}
	return ""
}

func parseResources(value string) ([]resourceEntry, []string) {
	var entries []resourceEntry
	var errs []string
	for _, line := range strings.Split(value, "\n") {
		m := resourceLineRe.FindStringSubmatch(line)
		if m == nil {
			errs = append(errs, fmt.Sprintf("resources: expected \"sha256:<hex> <ref>\", got %s", jsonString(line)))
			continue
		}
		ref := m[2]
		if e := ValidateResourceRef(ref); e != "" {
			errs = append(errs, "resources: "+e)
		}
		entries = append(entries, resourceEntry{Hash: m[1], Ref: ref, Remote: httpsPrefixRe.MatchString(ref)})
	}
	return entries, errs
}

func formatResources(items []ResourceItem) (string, error) {
	lines := make([]string, 0, len(items))
	for _, it := range items {
		if e := ValidateResourceRef(it.Ref); e != "" {
			return "", errors.New(e)
		}
		sum := sha256.Sum256(it.Bytes)
		lines = append(lines, "sha256:"+toHex(sum[:])+" "+it.Ref)
	}
	return strings.Join(lines, "\n"), nil
}

const MaxResourceBytes = 50 * 1024 * 1024

const maxRevocationListBytes = 5 * 1024 * 1024

type httpStatusError struct{ Status int }

func (e *httpStatusError) Error() string { return fmt.Sprintf("HTTP %d", e.Status) }

func FetchResource(ctx context.Context, client *http.Client, url string, maxBytes int64) ([]byte, error) {
	if !httpsPrefixRe.MatchString(url) {
		return nil, errors.New("only https:// URLs are fetched")
	}
	if client == nil {
		client = SafeHTTPClient(30 * time.Second)
	}
	if maxBytes <= 0 {
		maxBytes = MaxResourceBytes
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, &httpStatusError{Status: res.StatusCode}
	}
	if res.Request != nil && res.Request.URL != nil && res.Request.URL.Scheme != "https" {
		return nil, errors.New("redirected to a non-https URL")
	}
	if res.ContentLength > maxBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxBytes)
	}
	return b, nil
}

var ErrForbiddenAddress = errors.New("refusing to connect to a private, loopback, or link-local address")

func isForbiddenIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, p := range forbiddenPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	// SSRF: a gateway forwards these to the IPv4 address they carry
	for _, e := range embeddedIPv4Prefixes {
		if e.prefix.Contains(ip) {
			b := ip.As16()
			return isForbiddenIP(netip.AddrFrom4([4]byte(b[e.offset : e.offset+4])))
		}
	}
	return false
}

var embeddedIPv4Prefixes = []struct {
	prefix netip.Prefix
	offset int
}{
	{netip.MustParsePrefix("::/96"), 12},        // IPv4-compatible (deprecated)
	{netip.MustParsePrefix("64:ff9b::/96"), 12}, // well-known NAT64
	{netip.MustParsePrefix("2002::/16"), 2},     // 6to4
}

var forbiddenPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // this network
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, incl. broadcast
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001::/32"),       // Teredo
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("fec0::/10"),       // deprecated site-local
	netip.MustParsePrefix("::ffff:0:0:0/96"), // IPv4-translated
}

// SSRF: checks the resolved IP being dialled, not the hostname
func safeDialControl(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrForbiddenAddress, address)
	}
	if isForbiddenIP(ap.Addr()) {
		return fmt.Errorf("%w: %s", ErrForbiddenAddress, ap.Addr())
	}
	return nil
}

func SafeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: safeDialControl}
	tr := &http.Transport{
		// a proxy would bypass the dial-time address check
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("redirected to a non-https URL")
			}
			return nil
		},
	}
}

type ResourceLoader func(ref string) ([]byte, error)

type ResourceCheckOptions struct {
	LoadResource     ResourceLoader
	FetchResources   bool
	FetchClient      *http.Client
	MaxResourceBytes int64
}

func checkResources(ctx context.Context, entries []resourceEntry, o *ResourceCheckOptions) []ResourceResult {
	out := []ResourceResult{}
	for _, e := range entries {
		var data []byte
		if e.Remote {
			if !o.FetchResources {
				out = append(out, ResourceResult{Ref: e.Ref, Status: ResourceNotChecked, Detail: "remote resources are fetched only on request"})
				continue
			}
			b, err := FetchResource(ctx, o.FetchClient, e.Ref, o.MaxResourceBytes)
			if err != nil {
				out = append(out, ResourceResult{Ref: e.Ref, Status: ResourceUnreachable, Detail: err.Error()})
				continue
			}
			data = b
		} else {
			if o.LoadResource == nil {
				out = append(out, ResourceResult{Ref: e.Ref, Status: ResourceNotChecked, Detail: "the document's directory is not available"})
				continue
			}
			b, err := o.LoadResource(e.Ref)
			if err != nil {
				out = append(out, ResourceResult{Ref: e.Ref, Status: ResourceMissing, Detail: "could not be read: " + err.Error()})
				continue
			}
			if b == nil {
				out = append(out, ResourceResult{Ref: e.Ref, Status: ResourceMissing})
				continue
			}
			data = b
		}
		sum := sha256.Sum256(data)
		got := toHex(sum[:])
		if got == e.Hash {
			out = append(out, ResourceResult{Ref: e.Ref, Status: ResourceOK})
		} else {
			out = append(out, ResourceResult{Ref: e.Ref, Status: ResourceMismatch, Detail: "sha256:" + got})
		}
	}
	return out
}

// ECMAScript \s as a character class (RE2 \s is ASCII-only and lacks \v)
const jsSpaceClass = `\t\n\v\f\r \x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

var (
	mdImageRe = regexp.MustCompile(`!\[[^\]]*\]\([` + jsSpaceClass + `]*<?([^)>` + jsSpaceClass + `]+)>?(?:[` + jsSpaceClass + `]+"[^"]*")?[` + jsSpaceClass + `]*\)`)
	htmlImgRe = regexp.MustCompile(`(?i)<img\b[^>]*\bsrc[` + jsSpaceClass + `]*=[` + jsSpaceClass + `]*["']([^"']+)["']`)
)

func FindLocalImages(markdown string) []string {
	var refs []string
	seen := map[string]bool{}
	add := func(r string) {
		if !seen[r] {
			seen[r] = true
			refs = append(refs, r)
		}
	}
	// same order as the TS core: all ![..](..) matches, then <img>, per line
	for _, fl := range linesWithFence(markdown) {
		if fl.InFence {
			continue
		}
		for _, m := range mdImageRe.FindAllStringSubmatch(fl.Line, -1) {
			add(m[1])
		}
		for _, m := range htmlImgRe.FindAllStringSubmatch(fl.Line, -1) {
			add(m[1])
		}
	}
	var out []string
	for _, r := range refs {
		if schemeRe.MatchString(r) || strings.HasPrefix(r, "#") || ValidateResourceRef(r) != "" {
			continue
		}
		out = append(out, r)
	}
	return out
}

// SSRF/DoS: a ref must stay inside dir after symlinks and be a regular file (no FIFO, device, or Windows device name)
func DirResourceLoader(dir string) ResourceLoader {
	return func(ref string) ([]byte, error) {
		if e := ValidateResourceRef(ref); e != "" {
			return nil, errors.New(e)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			return nil, err
		}
		defer root.Close()
		name := filepath.FromSlash(ref)
		// checked before Open, which would block on a FIFO
		st, err := root.Stat(name)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, resourcePathError(err)
		}
		if !st.Mode().IsRegular() {
			return nil, errors.New("not a regular file")
		}
		f, err := root.Open(name)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, resourcePathError(err)
		}
		defer f.Close()
		if st, err = f.Stat(); err != nil || !st.Mode().IsRegular() {
			return nil, errors.New("not a regular file")
		}
		b, err := io.ReadAll(io.LimitReader(f, MaxResourceBytes+1))
		if err != nil {
			return nil, err
		}
		if len(b) > MaxResourceBytes {
			return nil, fmt.Errorf("larger than %d bytes", MaxResourceBytes)
		}
		return b, nil
	}
}

// drops the OS path from the message; callers add the ref
func resourcePathError(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
