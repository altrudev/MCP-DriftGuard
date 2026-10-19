//go:build linux

package observe

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func stdioSandboxCommand(target string, args []string) (string, []string, error) {
	mode := os.Getenv("MCPDRIFT_STDIO_SANDBOX")
	if mode == "" {
		return target, args, nil
	}
	if mode != "bwrap" {
		return "", nil, errors.New("unsupported stdio sandbox mode")
	}
	wrapper, err := exec.LookPath("bwrap")
	if err != nil {
		return "", nil, errors.New("requested stdio sandbox unavailable")
	}
	flags := []string{"--die-with-parent", "--unshare-all", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/run", "--chdir", "/", "--", target}
	// Operator-opted read-only access for a specific server package stored under
	// /tmp. Avoid exposing the rest of the host's temporary files.
	if configured := os.Getenv("MCPDRIFT_STDIO_SANDBOX_RO_DIR"); configured != "" {
		real, err := filepath.EvalSymlinks(configured)
		if err != nil || !filepath.IsAbs(configured) || !strings.HasPrefix(real, "/tmp/") || real == "/tmp" {
			return "", nil, errors.New("invalid sandbox read-only package directory")
		}
		info, err := os.Stat(real)
		if err != nil || !info.IsDir() {
			return "", nil, errors.New("sandbox package directory is unavailable")
		}
		// Recreate the path beneath private /tmp; each parent is only a directory,
		// not a bind of its host-side contents.
		parent := filepath.Dir(real)
		var hierarchy []string
		for parent != "/tmp" && parent != "/" {
			hierarchy = append([]string{parent}, hierarchy...)
			parent = filepath.Dir(parent)
		}
		flags = flags[:len(flags)-2]
		for _, dir := range hierarchy {
			flags = append(flags, "--dir", dir)
		}
		flags = append(flags, "--ro-bind", real, real, "--", target)
	}
	return wrapper, append(flags, args...), nil
}
