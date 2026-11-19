package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestKnownListRemove(t *testing.T) {
	out, _ := isolate(t)
	path := knownSignersPath()
	other := "es256:" + strings.Repeat("A", 88)
	if err := updateKnownSigners(path, func(m map[string]string) {
		m["bob@laptop"] = "ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
		m["carol@phone"] = other
	}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if err := runKnownList(true); err != nil {
		t.Fatal(err)
	}
	var list []knownSigner
	if err := json.Unmarshal(out.Bytes(), &list); err != nil || len(list) != 2 {
		t.Fatalf("list %q %v", out.String(), err)
	}
	if list[0].Signer != "bob@laptop" || list[0].Fingerprint != "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8" {
		t.Fatalf("bob: %+v", list[0])
	}
	if !strings.HasPrefix(list[1].Fingerprint, "SHA256:") || strings.HasSuffix(list[1].Fingerprint, "=") {
		t.Fatalf("carol: %+v", list[1])
	}
	if err := runKnownRemove("bob@laptop"); err != nil {
		t.Fatal(err)
	}
	if err := runKnownRemove("bob@laptop"); exitCode(err) != exitUsage {
		t.Fatalf("second remove: %v", err)
	}
	if m := readKnownSigners(path); len(m) != 1 || m["carol@phone"] != other {
		t.Fatalf("after remove: %v", m)
	}
}

func TestTofuStoreKeepsOtherRecords(t *testing.T) {
	isolate(t)
	s := openTofuStore()
	_ = s.Set("bob@laptop", "ed25519:AAAA")
	if err := updateKnownSigners(knownSignersPath(), func(m map[string]string) { m["carol@phone"] = "ed25519:BBBB" }); err != nil {
		t.Fatal(err)
	}
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	m := readKnownSigners(filepath.Clean(knownSignersPath()))
	if m["bob@laptop"] != "ed25519:AAAA" || m["carol@phone"] != "ed25519:BBBB" {
		t.Fatalf("records: %v", m)
	}
}
