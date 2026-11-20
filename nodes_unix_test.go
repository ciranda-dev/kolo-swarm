//go:build unix

package koloswarm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// loadWithin runs LoadNodes with a deadline, since a FIFO could block it.
func loadWithin(t *testing.T, path string) ([]string, error) {
	t.Helper()
	type result struct {
		nodes []string
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := LoadNodes(path)
		ch <- result{n, err}
	}()
	select {
	case r := <-ch:
		return r.nodes, r.err
	case <-time.After(5 * time.Second):
		t.Fatalf("LoadNodes(%s) blocked", path)
		return nil, nil
	}
}

func TestLoadNodesSpecialFiles(t *testing.T) {
	opened := false
	nodeHooks.fileOpened = func(string) { opened = true }
	t.Cleanup(func() { nodeHooks.fileOpened = nil })
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	dev := filepath.Join(dir, "zero")
	if err := os.Symlink("/dev/zero", dev); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{fifo, dev} {
		if _, err := loadWithin(t, p); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "not a regular file") || opened {
			t.Errorf("%s: %v, opened %v; want refused before it is opened", p, err, opened)
		}
	}
}

func TestLoadNodesSwappedAfterOpen(t *testing.T) {
	p := writeNodeFile(t, "127.0.0.1:7447\n")
	nodeHooks.fileOpened = func(path string) {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { nodeHooks.fileOpened = nil })
	if got, err := loadWithin(t, p); err != nil || len(got) != 1 {
		t.Fatalf("LoadNodes = %q, %v; want the file that was opened", got, err)
	}
}

func TestLoadNodesUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	p := writeNodeFile(t, "secret-content:1\n")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	_, err := LoadNodes(p)
	if !errors.Is(err, os.ErrPermission) || !strings.Contains(err.Error(), p) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unreadable file: %v", err)
	}
}

func TestLoadNodesSwappedBeforeOpen(t *testing.T) {
	p := writeNodeFile(t, "127.0.0.1:7447\n")
	nodeHooks.fileChecked = func(path string) {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { nodeHooks.fileChecked = nil })
	if _, err := loadWithin(t, p); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("error %v, want the FIFO swapped in after the path check refused", err)
	}
}
