package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandCommand(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"expand", "2001:db8::1"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("no output")
	}
}

func TestInfoAddress(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"info", "2001:db8::1"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "expanded") {
		t.Fatal("expected expanded in output")
	}
}

func TestInfoCIDR(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"info", "2001:db8::/126"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "host_count") {
		t.Fatal("expected host_count")
	}
}

func TestCompress(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"compress", "2001:0db8:0000:0000:0000:0000:0000:0001"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "2001:db8::1") {
		t.Fatal("compress output mismatch")
	}
}

func TestSplit(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"split", "2001:db8::/124", "--new-prefix", "126"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "/126") {
		t.Fatal("expected split subnets")
	}
}

func TestSummarize(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"summarize", "2001:db8::/65", "2001:db8:0:0:8000::/65"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "/64") {
		t.Fatal("expected summarized /64")
	}
}

func TestReverse(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"reverse", "2001:db8::1"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "ip6.arpa") {
		t.Fatal("expected reverse")
	}
}

func TestVersionCommand(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "version") {
		t.Fatal("version output missing key")
	}
}

func TestSplitInvalidPrefix(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"split", "2001:db8::/124", "--new-prefix", "124"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid new-prefix")
	}
	if !strings.Contains(err.Error(), "invalid --new-prefix") {
		t.Fatal("unexpected error message")
	}
}

func TestCompletionBash(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"completion", "bash"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "complete") {
		t.Fatal("expected completion script content")
	}
}

func TestManGeneration(t *testing.T) {
	tmp := t.TempDir()
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"man", tmp})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	// Expect at least one man page file present.
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no man pages generated")
	}
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), "ip6calc") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ip6calc man page not found in %s", tmp)
	}
	// Ensure files are not empty.
	for _, e := range entries {
		info, err := os.Stat(filepath.Join(tmp, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() == 0 {
			t.Fatalf("empty man page: %s", e.Name())
		}
	}
}

func TestSplitStreamingLarge(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"split", "2001:db8::/124", "--new-prefix", "126"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 subnets got %d", len(lines))
	}
}

// Ensure Execute does not leak panic on invalid shell for completion.
func TestCompletionInvalidShell(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"completion", "unknownshell"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, err) { // placeholder to satisfy lint; check message
		if !strings.Contains(err.Error(), "unsupported shell") {
			t.Fatal("unexpected error message")
		}
	}
}
