//go:build linux

package observe

import (
	"os/exec"
	"strings"
	"testing"
)

func TestStdioSandboxRejectsUnsupportedMode(t *testing.T) {
	t.Setenv("MCPDRIFT_STDIO_SANDBOX", "unknown")
	_, _, err := stdioSandboxCommand("/bin/true", nil)
	if err == nil {
		t.Fatal("unsupported sandbox mode accepted")
	}
}
func TestStdioSandboxIsolation(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed")
	}
	t.Setenv("MCPDRIFT_STDIO_SANDBOX", "bwrap")
	cmd, args, err := stdioSandboxCommand("/bin/sh", []string{"-c", "test ! -w /etc && test ! -e /tmp/nonexistent-private-fixture && cat /proc/net/dev"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") {
			t.Skip("user namespaces disabled")
		}
		t.Fatalf("sandbox enforcement failed: %v %s", err, out)
	}
	if !strings.Contains(string(out), "lo:") {
		t.Fatal("expected loopback interface")
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, ":") && !strings.Contains(line, "lo:") {
			t.Fatalf("network interface exposed: %s", line)
		}
	}
}
