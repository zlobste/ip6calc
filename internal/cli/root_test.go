package cli

import (
	"bytes"
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
