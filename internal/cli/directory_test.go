package cli

import (
	"strings"
	"testing"
)

func TestDirectoryTrustList(t *testing.T) {
	out, _ := isolate(t)
	if err := runTrust("add", "https://keys.example.org/"); err != nil {
		t.Fatal(err)
	}
	if err := runTrust("add", "http://insecure.example"); err == nil {
		t.Fatal("accepted an http directory")
	}
	if err := runTrust("list", ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "https://keys.mdsig.dev  (default)") || !strings.Contains(out.String(), "https://keys.example.org\n") {
		t.Fatalf("list: %q", out.String())
	}
	dirs, err := trustedDirectories([]string{"https://keys.extra.example"})
	if err != nil || strings.Join(dirs, " ") != "https://keys.mdsig.dev https://keys.example.org https://keys.extra.example" {
		t.Fatalf("dirs=%v err=%v", dirs, err)
	}
	if err := runTrust("remove", "https://keys.example.org"); err != nil {
		t.Fatal(err)
	}
	if err := runTrust("remove", "https://keys.example.org"); err == nil {
		t.Fatal("removed a directory twice")
	}
	if dirs, _ := trustedDirectories(nil); len(dirs) != 1 {
		t.Fatalf("after remove: %v", dirs)
	}
}

func TestSignDirectoryFlags(t *testing.T) {
	isolate(t)
	if err := runSign(&signOptions{method: "tofu", signer: "bob@laptop", noEmbedKey: true}, "x.md"); err == nil || !strings.Contains(err.Error(), "--no-embed-key") {
		t.Fatalf("--no-embed-key with tofu: %v", err)
	}
}
