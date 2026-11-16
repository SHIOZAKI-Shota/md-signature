package mdsig

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// --- SSRF guard

func TestForbiddenIPEmbeddedIPv4(t *testing.T) {
	forbidden := []string{
		"::127.0.0.1", "::10.0.0.1", "::a9fe:a9fe",
		"64:ff9b::7f00:1", "64:ff9b::10.1.2.3", "64:ff9b::169.254.169.254", "64:ff9b:1::1",
		"2002:7f00:1::", "2002:c0a8:101::1", "2002:a9fe:a9fe::1",
		"2001::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
		"ff02::1", "ff0e::1", "::1", "::", "::ffff:127.0.0.1", "127.0.0.1", "169.254.169.254",
	}
	for _, s := range forbidden {
		if !IsForbiddenIP(netip.MustParseAddr(s)) {
			t.Errorf("%s must be forbidden", s)
		}
	}
	allowed := []string{"8.8.8.8", "2606:4700:4700::1111", "64:ff9b::808:808", "2002:808:808::1", "2001:4860:4860::8888"}
	for _, s := range allowed {
		if IsForbiddenIP(netip.MustParseAddr(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

func TestDefaultResolverClientRefusesLoopback(t *testing.T) {
	_, err := FetchKeysFile(context.Background(), "127.0.0.1/x", &ResolveOptions{})
	if err == nil || !strings.Contains(err.Error(), ErrForbiddenAddress.Error()) {
		t.Fatalf("got %v", err)
	}
}

func TestSafeClientRefusesNonHTTPSRedirect(t *testing.T) {
	c := SafeHTTPClient(5 * time.Second)
	target, _ := http.NewRequest(http.MethodGet, "http://example.com/x.keys", nil)
	if err := c.CheckRedirect(target, []*http.Request{target}); err == nil {
		t.Fatal("redirect to http must be refused")
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := c.Get(srv.URL); !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("loopback dial: got %v", err)
	}
}

// --- local resources

func TestDirResourceLoaderStaysInside(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "doc")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(base, "secret.txt"), []byte("secret"), 0o644)
	os.WriteFile(filepath.Join(dir, "sub", "real.png"), []byte("data"), 0o644)
	load := DirResourceLoader(dir)

	if b, err := load("sub/real.png"); err != nil || string(b) != "data" {
		t.Fatalf("plain file: %q %v", b, err)
	}
	if b, err := load("absent.png"); b != nil || err != nil {
		t.Fatalf("absent file: %q %v", b, err)
	}
	if _, err := load("sub"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory: %v", err)
	}
	if runtime.GOOS == "windows" {
		for _, ref := range []string{"CON", "NUL", "sub/COM1"} {
			if b, err := load(ref); err == nil && b != nil {
				t.Errorf("%s was read", ref)
			}
		}
		return
	}
	if err := os.Symlink(filepath.Join("sub", "real.png"), filepath.Join(dir, "inside.png")); err != nil {
		t.Skip("symlinks not available")
	}
	if b, err := load("inside.png"); err != nil || string(b) != "data" {
		t.Fatalf("symlink inside the directory: %q %v", b, err)
	}
	os.Symlink(filepath.Join("..", "secret.txt"), filepath.Join(dir, "rel.png"))
	os.Symlink(filepath.Join(base, "secret.txt"), filepath.Join(dir, "abs.png"))
	os.Symlink(base, filepath.Join(dir, "up"))
	os.Symlink("/dev/zero", filepath.Join(dir, "zero.png"))
	for _, ref := range []string{"rel.png", "abs.png", "up/secret.txt", "zero.png"} {
		if b, err := load(ref); err == nil {
			t.Errorf("%s escaped the directory: %q", ref, b)
		}
	}
}

func TestDirResourceLoaderSizeLimit(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxResourceBytes + 1); err != nil {
		t.Skip("sparse file not available")
	}
	f.Close()
	if _, err := DirResourceLoader(dir)("big.bin"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}
