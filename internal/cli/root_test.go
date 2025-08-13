package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestExpandCommand(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"expand", "2001:db8::1"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("no output")
	}
}

func TestInfoAddress(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"info", "2001:db8::1"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "expanded") {
		t.Fatal("expected expanded in output")
	}
}

func TestInfoCIDR(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"info", "2001:db8::/126"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "host_count") {
		t.Fatal("expected host_count")
	}
}

func TestCompress(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"compress", "2001:0db8:0000:0000:0000:0000:0000:0001"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "2001:db8::1") {
		t.Fatal("compress output mismatch")
	}
}

func TestSplit(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"split", "2001:db8::/124", "--new-prefix", "126"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "/126") {
		t.Fatal("expected split subnets")
	}
}

func TestSummarize(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"summarize", "2001:db8::/65", "2001:db8:0:0:8000::/65"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "/64") {
		t.Fatal("expected summarized /64")
	}
}

func TestReverse(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"reverse", "2001:db8::1"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "ip6.arpa") {
		t.Fatal("expected reverse")
	}
}
