package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Focused tests keeping coverage high without redundancy.

func TestInfoAddressAndCIDR(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"info", "2001:db8::1"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "expanded") {
		t.Fatalf("info address failed: %v output=%s", err, buf.String())
	}
	buf.Reset()
	cmd = NewRootCmd(buf)
	cmd.SetArgs([]string{"info", "2001:db8::/126"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "host_count") {
		t.Fatalf("info cidr failed: %v output=%s", err, buf.String())
	}
}

func TestExpandCompress(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"expand", "2001:db8::1"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "2001:0db8") {
		t.Fatalf("expand failed: %v", err)
	}
	buf.Reset()
	cmd = NewRootCmd(buf)
	cmd.SetArgs([]string{"compress", "2001:0db8:0000:0000:0000:0000:0000:0001"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "2001:db8::1") {
		t.Fatalf("compress failed: %v", err)
	}
}

func TestSplitSummarizeSupernet(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"split", "2001:db8::/124", "--new-prefix", "126"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "/126") {
		t.Fatalf("split failed: %v", err)
	}
	buf.Reset()
	cmd = NewRootCmd(buf)
	cmd.SetArgs([]string{"summarize", "2001:db8::/65", "2001:db8:0:0:8000::/65"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "/64") {
		t.Fatalf("summarize failed: %v", err)
	}
	buf.Reset()
	cmd = NewRootCmd(buf)
	cmd.SetArgs([]string{"supernet", "2001:db8::/65", "2001:db8:0:0:8000::/65"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "/64") {
		t.Fatalf("supernet failed: %v", err)
	}
}

func TestRangeEnumerateRandom(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"range", "2001:db8::1-2001:db8::ff"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "/128") {
		t.Fatalf("range failed: %v", err)
	}
	buf.Reset()
	cmd = NewRootCmd(buf)
	cmd.SetArgs([]string{"enumerate", "2001:db8::/126", "--limit", "2"})
	if err := cmd.Execute(); err != nil || strings.Count(strings.TrimSpace(buf.String()), "\n")+1 != 2 {
		t.Fatalf("enumerate failed: %v", err)
	}
	buf.Reset()
	cmd = NewRootCmd(buf)
	cmd.SetArgs([]string{"random", "address", "2001:db8::/126", "--count", "2"})
	if err := cmd.Execute(); err != nil || strings.Count(strings.TrimSpace(buf.String()), "\n")+1 != 2 {
		t.Fatalf("random address failed: %v", err)
	}
}

func TestDiffReverseVersionCompletionDocsMan(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"diff", "2001:db8::/65", "2001:db8::/64"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "overlap") {
		t.Fatalf("diff failed: %v", err)
	}
	buf.Reset()
	cmd = NewRootCmd(buf)
	cmd.SetArgs([]string{"reverse", "2001:db8::1"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "ip6.arpa") {
		t.Fatalf("reverse failed: %v", err)
	}
	buf.Reset()
	cmd = NewRootCmd(buf)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "version") {
		t.Fatalf("version failed: %v", err)
	}
	// completion
	buf.Reset()
	cmd = NewRootCmd(buf)
	cmd.SetArgs([]string{"completion", "bash"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "complete") {
		t.Fatalf("completion failed: %v", err)
	}
	// docs + man generation
	tmp := t.TempDir()
	buf.Reset()
	cmd = NewRootCmd(buf)
	cmd.SetArgs([]string{"docs", tmp})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("docs failed: %v", err)
	}
	entries, err := os.ReadDir(tmp)
	if err != nil || len(entries) == 0 {
		t.Fatalf("expected docs files: %v", err)
	}
	buf.Reset()
	cmd = NewRootCmd(buf)
	cmd.SetArgs([]string{"man", tmp})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("man failed: %v", err)
	}
	// sanity: at least one man file
	found := false
	if err := filepath.WalkDir(tmp, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(d.Name(), ".1") {
			found = true
		}
		return nil
	}); err != nil {
		// walk failed
		t.Fatalf("walk dir failed: %v", err)
	}
	if !found {
		t.Fatal("no man pages found")
	}
}

func TestEnvAndFormatVariants(t *testing.T) {
	buf := &bytes.Buffer{}
	if err := os.Setenv("IP6CALC_FORMAT", "json"); err != nil {
		// Fail early if env cannot be set
		t.Fatalf("failed to set env: %v", err)
	}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"info", "2001:db8::1"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "schema") {
		t.Fatalf("env format failed: %v output=%s", err, buf.String())
	}
	buf.Reset()
	cmd = NewRootCmd(buf)
	cmd.SetArgs([]string{"info", "2001:db8::/125", "-o", "yaml"})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "host_count") {
		t.Fatalf("yaml output failed: %v", err)
	}
}

func TestErrorPaths(t *testing.T) {
	// invalid new-prefix (expect error)
	cmd := NewRootCmd(&bytes.Buffer{})
	cmd.SetArgs([]string{"split", "2001:db8::/124", "--new-prefix", "124"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "invalid --new-prefix") {
		t.Fatalf("expected invalid new-prefix error")
	}
	// unsupported shell
	cmd = NewRootCmd(&bytes.Buffer{})
	cmd.SetArgs([]string{"completion", "unknown"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unsupported shell") {
		t.Fatalf("expected unsupported shell error")
	}
	// overlap flag
	cmd = NewRootCmd(&bytes.Buffer{})
	cmd.SetArgs([]string{"summarize", "--fail-on-overlap", "2001:db8::/65", "2001:db8:0:0:8000::/65"}) // non-overlapping pair should succeed
	if err := cmd.Execute(); err != nil {
		// If they summarize to a /64 they overlapped incorrectly
		t.Fatalf("unexpected error on non-overlap: %v", err)
	}
	// explicit overlap scenario
	cmd = NewRootCmd(&bytes.Buffer{})
	cmd.SetArgs([]string{"summarize", "--fail-on-overlap", "2001:db8::/65", "2001:db8::/64"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "overlap detected") {
		t.Fatalf("expected overlap error")
	}
	// split force threshold (trigger error then success with --force)
	if err := os.Setenv("IP6CALC_SPLIT_FORCE_THRESHOLD", "8"); err != nil {
		// fail if we cannot set env
		t.Fatalf("failed to set env: %v", err)
	}
	cmd = NewRootCmd(&bytes.Buffer{})
	cmd.SetArgs([]string{"split", "2001:db8::/120", "--new-prefix", "124"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "too many subnets") {
		t.Fatalf("expected split too large error")
	}
	cmd = NewRootCmd(&bytes.Buffer{})
	cmd.SetArgs([]string{"split", "2001:db8::/120", "--new-prefix", "124", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected forced split success: %v", err)
	}
}

func TestToFromInt(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"to-int", "2001:db8::1"})
	if err := cmd.Execute(); err != nil {
		// retry with explicit human output to avoid env interference
		buf.Reset()
		cmd = NewRootCmd(buf)
		cmd.SetArgs([]string{"-o", "human", "to-int", "2001:db8::1"})
		if err2 := cmd.Execute(); err2 != nil {
			t.Fatalf("to-int failed: %v", err2)
		}
	}
	val := strings.TrimSpace(buf.String())
	// If JSON/YAML wrapped, extract the numeric value
	if strings.Contains(val, "schema") {
		// attempt JSON decode
		var wrapper map[string]any
		if err := json.Unmarshal([]byte(val), &wrapper); err == nil {
			if data, ok := wrapper["data"].(string); ok {
				val = data
			}
		}
		// strip braces or quotes remnants
		val = strings.Trim(val, "{} \n\r\t\"")
		// fallback: search for first 34+ digit sequence
		for i := 0; i < len(val); i++ {
			if val[i] >= '0' && val[i] <= '9' {
				j := i
				for j < len(val) && val[j] >= '0' && val[j] <= '9' {
					j++
				}
				val = val[i:j]
				break
			}
		}
	}
	if val == "" {
		t.Fatal("empty int output")
	}
	buf.Reset()
	cmd = NewRootCmd(buf)
	cmd.SetArgs([]string{"from-int", val})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "2001:db8::1") {
		t.Fatalf("from-int failed: %v (val=%s output=%s)", err, val, buf.String())
	}
}

func TestJSONHostCountFields(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCmd(buf)
	cmd.SetArgs([]string{"--output", "json", "info", "2001:db8::/64"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("json info failed: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		trim := strings.TrimSpace(buf.String())
		if err2 := json.Unmarshal([]byte(trim), &m); err2 != nil {
			t.Fatalf("unmarshal failed: %v", err2)
		}
	}
	for _, k := range []string{"host_count", "host_count_power", "host_count_approx"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing field %s", k)
		}
	}
}
