package mdsig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var examplesDir = filepath.Join("..", "examples")

func readExample(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(examplesDir, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type keysJSON struct {
	GitHosting map[string]struct {
		KeysFile string `json:"keys_file"`
	} `json:"git-hosting"`
	DNS map[string]struct {
		TXT string `json:"txt"`
	} `json:"dns"`
	Now   string            `json:"now"`
	Fetch map[string]string `json:"fetch"`
}

func loadKeysJSON(t *testing.T) keysJSON {
	t.Helper()
	var keys keysJSON
	if err := json.Unmarshal([]byte(readExample(t, "keys.json")), &keys); err != nil {
		t.Fatal(err)
	}
	return keys
}

type expectedEntry struct {
	OK         bool        `json:"ok"`
	Signatures []string    `json:"signatures"`
	Error      string      `json:"error"`
	TSA        []*string   `json:"tsa"`
	Agreement  string      `json:"agreement"`
	Partial    *[][]string `json:"partial"`
	Resources  [][]string  `json:"resources"`
	Revocation []*string   `json:"revocation"`
	Pgp        []struct {
		KeySource string `json:"keySource"`
		KeyAlg    string `json:"keyAlg"`
	} `json:"pgp"`
}

func keysJSONResolvers(t *testing.T) map[string]Resolver {
	keys := loadKeysJSON(t)
	return map[string]Resolver{
		"git-hosting": ResolverFunc(func(_ context.Context, f map[string]string, _ *ResolveOptions) (ResolveResult, error) {
			e, ok := keys.GitHosting[f["signer"]]
			if !ok {
				return ResolveResult{}, &ResolutionError{Kind: KindNotFound, Msg: "not in keys.json"}
			}
			return GitHostingKeysFromText(f, "keys.json", e.KeysFile)
		}),
		"dns": ResolverFunc(func(_ context.Context, f map[string]string, _ *ResolveOptions) (ResolveResult, error) {
			name := DNSName(f)
			e, ok := keys.DNS[name]
			if !ok {
				return ResolveResult{}, &ResolutionError{Kind: KindNotFound, Msg: "not in keys.json"}
			}
			return DNSKeysFromRecords(f, name, []string{e.TXT})
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respond(req *http.Request, status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)),
		Header: http.Header{}, Request: req,
	}
}

func examplesFetchClient(t *testing.T, calls *int) *http.Client {
	keys := loadKeysJSON(t)
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if calls != nil {
			*calls++
		}
		file, ok := keys.Fetch[r.URL.String()]
		if !ok {
			return nil, fmt.Errorf("network disabled in tests: %s", r.URL)
		}
		return respond(r, 200, []byte(readExample(t, file))), nil
	})}
}

func examplesVerifyOptions(t *testing.T) *VerifyOptions {
	keys := loadKeysJSON(t)
	now, err := time.Parse(time.RFC3339, keys.Now)
	if err != nil {
		t.Fatal(err)
	}
	return &VerifyOptions{
		ResolveOptions: ResolveOptions{PgpClient: examplesFetchClient(t, nil)},
		Resolvers:      keysJSONResolvers(t),
		ResourceCheckOptions: ResourceCheckOptions{
			LoadResource: DirResourceLoader(examplesDir),
			FetchClient:  examplesFetchClient(t, nil),
		},
		Now: now,
		TSA: TSAVerifyOptions{Roots: sslcomRoots(t)},
	}
}

func TestExamplesCompliance(t *testing.T) {
	var expected map[string]expectedEntry
	if err := json.Unmarshal([]byte(readExample(t, "expected.json")), &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected) == 0 {
		t.Fatal("expected.json is empty")
	}
	for file, exp := range expected {
		t.Run(file, func(t *testing.T) {
			r := VerifyDocument(context.Background(), readExample(t, file), examplesVerifyOptions(t))
			if r.OK != exp.OK {
				t.Errorf("ok = %v, want %v (error %q)", r.OK, exp.OK, r.Error)
			}
			got := []string{}
			for _, s := range r.Signatures {
				if s.Status == StatusValid {
					got = append(got, "valid")
				} else {
					got = append(got, s.Status+":"+s.Code)
				}
			}
			if !reflect.DeepEqual(got, append([]string{}, exp.Signatures...)) {
				t.Errorf("signatures = %v, want %v", got, exp.Signatures)
				for _, s := range r.Signatures {
					t.Logf("  #%d %s:%s %s", s.Index, s.Status, s.Code, s.Message)
				}
			}
			if exp.Error == "unsigned-content" && !strings.Contains(r.Error, "unsigned content") {
				t.Errorf("error = %q, want unsigned content", r.Error)
			}
			if exp.TSA != nil {
				if len(exp.TSA) != len(r.Signatures) {
					t.Fatalf("tsa length mismatch")
				}
				for i, want := range exp.TSA {
					var g *string
					if r.Signatures[i].TSA != nil {
						g = &r.Signatures[i].TSA.Status
					}
					if (g == nil) != (want == nil) || (g != nil && *g != *want) {
						t.Errorf("tsa[%d] = %v, want %v", i, deref(g), deref(want))
					}
					if g != nil && *g == TSAOk && (!r.Signatures[i].TSA.Verified || !strings.HasPrefix(r.Signatures[i].TSA.Detail, "imprint matched; TSA signature verified (")) {
						t.Errorf("tsa detail = %q", r.Signatures[i].TSA.Detail)
					}
				}
			}
			wantAgreement := exp.Agreement
			if wantAgreement == "" {
				wantAgreement = AgreementNone
			}
			if r.Agreement.Status != wantAgreement {
				t.Errorf("agreement = %q, want %q", r.Agreement.Status, wantAgreement)
			}
			if exp.Partial != nil {
				var gotP [][]string
				for _, s := range r.Signatures {
					gotP = append(gotP, s.Partial)
				}
				if !reflect.DeepEqual(gotP, *exp.Partial) {
					t.Errorf("partial = %v, want %v", gotP, *exp.Partial)
				}
			}
			if exp.Resources != nil {
				var gotR [][]string
				for _, s := range r.Signatures {
					st := []string{}
					for _, x := range s.Resources {
						st = append(st, x.Status)
					}
					gotR = append(gotR, st)
				}
				if !reflect.DeepEqual(gotR, exp.Resources) {
					t.Errorf("resources = %v, want %v", gotR, exp.Resources)
				}
			}
			if exp.Pgp != nil {
				if len(exp.Pgp) != len(r.Signatures) {
					t.Fatalf("pgp length mismatch")
				}
				for i, want := range exp.Pgp {
					p := r.Signatures[i].Pgp
					if p == nil || p.KeySource != want.KeySource || p.KeyAlg != want.KeyAlg {
						t.Errorf("pgp[%d] = %+v, want %+v", i, p, want)
					}
				}
			}
			if exp.Revocation != nil {
				if len(exp.Revocation) != len(r.Signatures) {
					t.Fatalf("revocation length mismatch")
				}
				for i, want := range exp.Revocation {
					var g *string
					if r.Signatures[i].Revocation != nil {
						g = &r.Signatures[i].Revocation.Status
					}
					if (g == nil) != (want == nil) || (g != nil && *g != *want) {
						t.Errorf("revocation[%d] = %v, want %v", i, deref(g), deref(want))
					}
				}
			}
		})
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func TestCrossImplementation(t *testing.T) {
	bob := mustSigner(t, bobSeed)
	r, err := SignDocument(context.Background(), testBody, SignOptions{
		Signer: bob, Method: "tofu", SignerID: "bob@laptop", Role: "author", Reason: "Initial draft", TS: "2026-11-16T09:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := readExample(t, "valid-single.md")
	if r.Text != want {
		t.Fatalf("Go output differs from examples/valid-single.md\n--- go ---\n%s\n--- ts ---\n%s", r.Text, want)
	}

	crlf, err := SignDocument(context.Background(), strings.ReplaceAll(testBody, "\n", "\r\n"), SignOptions{
		Signer: bob, Method: "tofu", SignerID: "bob@laptop", Role: "author", TS: "2026-11-16T09:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if crlf.Text != readExample(t, "valid-crlf.md") {
		t.Fatal("Go output differs from examples/valid-crlf.md")
	}

	alice := mustSigner(t, aliceSeed)
	c1, err := SignDocument(context.Background(), testBody, SignOptions{
		Signer: alice, Method: "git-hosting", SignerID: "github.com/alice", Role: "author", Reason: "Initial draft", TS: "2026-11-16T09:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(readExample(t, "valid-cosigned.md"), c1.Text) {
		t.Fatal("Go git-hosting block differs from the first block of examples/valid-cosigned.md")
	}
}
