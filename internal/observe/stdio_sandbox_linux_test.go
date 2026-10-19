//go:build linux

package observe

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// The child deliberately creates a new process session inside the namespace.
// Killing the bwrap leader must close the inherited stdout pipe; otherwise an
// escaped descendant remains alive and this test times out.
func TestSandboxEscapedProcessGroupCannotKeepPipeOpen(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap unavailable")
	}
	t.Setenv("MCPDRIFT_STDIO_SANDBOX", "bwrap")
	executable, args, err := stdioSandboxCommand("/bin/sh", []string{"-c", "setsid /bin/sh -c 'echo child-ready; exec sleep 30' & wait"})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, args...)
	configureStdioProcess(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { terminateStdioProcess(cmd); _ = cmd.Wait() }()
	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() && scanner.Text() == "child-ready" {
			ready <- nil
		} else {
			ready <- fmt.Errorf("child did not start: %v", scanner.Err())
		}
	}()
	select {
	case e := <-ready:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("child startup timeout")
	}
	terminateStdioProcess(cmd)
	drained := make(chan error, 1)
	go func() { _, e := io.Copy(io.Discard, stdout); drained <- e }()
	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		t.Fatal("escaped process group retained stdout after sandbox termination")
	}
}

func TestSandboxApprovedReadOnlyPackageMount(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap unavailable")
	}
	dir := t.TempDir()
	// The sandbox requires a package subtree under /tmp, not a broad host mount.
	if !strings.HasPrefix(dir, "/tmp/") {
		t.Skip("test temporary directory not beneath /tmp")
	}
	if err := os.WriteFile(filepath.Join(dir, "server-marker"), []byte("scoped-package-data"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCPDRIFT_STDIO_SANDBOX", "bwrap")
	t.Setenv("MCPDRIFT_STDIO_SANDBOX_RO_DIR", dir)
	binary, args, err := stdioSandboxCommand("/bin/cat", []string{filepath.Join(dir, "server-marker")})
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(binary, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("read-only package mount unavailable: %v %s", err, output)
	}
	if string(output) != "scoped-package-data" {
		t.Fatalf("wrong package payload: %s", output)
	}
	for _, bad := range []string{"/", "/tmp", "relative/path"} {
		t.Setenv("MCPDRIFT_STDIO_SANDBOX_RO_DIR", bad)
		if _, _, err := stdioSandboxCommand("/bin/true", nil); err == nil {
			t.Fatalf("unscoped mount accepted %q", bad)
		}
	}
}
