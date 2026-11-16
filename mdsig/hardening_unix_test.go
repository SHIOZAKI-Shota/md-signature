//go:build !windows

package mdsig

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDirResourceLoaderRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.png"), 0o644); err != nil {
		t.Skip("mkfifo not available")
	}
	done := make(chan error, 1)
	go func() { _, err := DirResourceLoader(dir)("pipe.png"); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("fifo: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}
