package mdsig

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistrationMessageMatchesTS(t *testing.T) {
	sum := sha256.Sum256(registrationMessage("Y2hhbGxlbmdl", "alice@mail.example", "ed25519", "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw="))
	if got := hex.EncodeToString(sum[:]); got != "8d2281f7f7b6e585130540359012a38d638193afb414b2fbd5169881d1dbaf67" {
		t.Fatalf("message digest %s", got)
	}
	if got := directoryKeyURL("https://keys.mdsig.dev/", "alice@mail.example"); got != "https://keys.mdsig.dev/v1/keys/e29f4fb165e275d7e0fbbb5f7891bf1d1a69070aebb661cfdc3b3231f923967a" {
		t.Fatalf("lookup URL %s", got)
	}
}

func TestDirectoriesFromRecords(t *testing.T) {
	if got := directoriesFromRecords([]string{"v=mdsig1; k=ed25519; p=AAAA", "v=mdsig1; dir=https://keys.example.com/"}); len(got) != 1 || got[0] != "https://keys.example.com" {
		t.Fatalf("%v", got)
	}
	if got := directoriesFromRecords([]string{"v=mdsig1; dir=http://keys.example.com", "v=spf1 dir=https://x.example"}); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	if got := directoriesFromRecords([]string{"v=mdsig1; dir=https://a.example", "v=mdsig1; dir=https://b.example"}); len(got) != 2 {
		t.Fatalf("%v", got)
	}
}

func TestResolveDirectoryRules(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	signer, _ := SignerFromSeed(seed)
	email := "alice@mail.example"
	entry := map[string]any{"type": "ed25519", "key": toBase64(signer.PublicKey())}
	answers := map[string]any{
		directoryKeyURL("https://keys.mdsig.dev", email):     map[string]any{"email": "mallory@mail.example", "keys": []any{entry}},
		directoryKeyURL("https://keys.other.example", email): map[string]any{"email": email, "verified": "email", "keys": []any{entry}},
	}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		v, ok := answers[r.URL.String()]
		if !ok {
			return nil, errors.New("network down")
		}
		b, _ := json.Marshal(v)
		return respond(r, 200, b), nil
	})}
	noTXT := func(context.Context, string) ([]string, error) { return nil, nil }
	fields := map[string]string{"signer": email, "alg": "ed25519"}
	res, err := resolveDirectory(context.Background(), fields, &ResolveOptions{HTTPClient: client, LookupTXT: noTXT, KeyDirectories: []string{"https://keys.mdsig.dev", "https://keys.other.example"}})
	if err != nil || len(res.Keys) != 1 || !strings.Contains(res.Keys[0].Source, "keys.other.example (trusted list)") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	_, err = resolveDirectory(context.Background(), fields, &ResolveOptions{HTTPClient: client, LookupTXT: noTXT})
	var re *ResolutionError
	if !errors.As(err, &re) || re.Kind != KindNotFound {
		t.Fatalf("mismatched email: %v", err)
	}
	_, err = resolveDirectory(context.Background(), fields, &ResolveOptions{HTTPClient: client, LookupTXT: noTXT, KeyDirectories: []string{"https://down.example"}})
	if !errors.As(err, &re) || re.Kind != KindNetwork {
		t.Fatalf("unreachable: %v", err)
	}
	_, err = resolveDirectory(context.Background(), fields, &ResolveOptions{HTTPClient: client, LookupTXT: noTXT, KeyDirectories: []string{"http://insecure.example"}})
	if !errors.As(err, &re) || re.Kind != KindUnsupported {
		t.Fatalf("http directory: %v", err)
	}
	_, err = resolveDirectory(context.Background(), fields, &ResolveOptions{Offline: true})
	if !errors.As(err, &re) || re.Kind != KindOffline {
		t.Fatalf("offline: %v", err)
	}
}

func TestRegisterKeySendsAProofTheDirectoryCanCheck(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	signer, _ := SignerFromSeed(seed)
	var got map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/challenges":
			_, _ = w.Write([]byte(`{"challenge":"abc"}`))
		case "/v1/registrations":
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"pending"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	if err := RegisterKey(context.Background(), srv.Client(), srv.URL, "Alice@Mail.Example", signer, "laptop"); err != nil {
		t.Fatal(err)
	}
	if got["email"] != "alice@mail.example" || got["type"] != "ed25519" || got["challenge"] != "abc" || got["label"] != "laptop" {
		t.Fatalf("request %v", got)
	}
	proof := got["proof"].(map[string]any)
	sig, _ := fromBase64(proof["sig"].(string))
	if !ed25519.Verify(signer.PublicKey(), registrationMessage("abc", "alice@mail.example", "ed25519", got["key"].(string)), sig) {
		t.Fatal("the proof does not verify")
	}
}

func TestSignDirectory(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	signer, _ := SignerFromSeed(seed)
	ts := "2026-11-16T09:00:00Z"
	r, err := SignDocument(context.Background(), "# C\n", SignOptions{Signer: signer, Method: "directory", SignerID: "Alice@Mail.Example", TS: ts})
	if err != nil || r.Fields["signer"] != "alice@mail.example" || r.Fields["pubkey"] == "" {
		t.Fatalf("fields=%v err=%v", r.Fields, err)
	}
	r, err = SignDocument(context.Background(), "# C\n", SignOptions{Signer: signer, Method: "directory", SignerID: "alice@mail.example", TS: ts, OmitKeySnapshot: true})
	if err != nil || r.Fields["pubkey"] != "" {
		t.Fatalf("fields=%v err=%v", r.Fields, err)
	}
	if _, err := SignDocument(context.Background(), "# C\n", SignOptions{Signer: signer, Method: "directory", SignerID: "not-an-email", TS: ts}); err == nil {
		t.Fatal("accepted a non-email signer")
	}
}
