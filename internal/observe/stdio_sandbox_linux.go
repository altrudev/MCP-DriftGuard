//go:build linux

package observe

import (
	"errors"
	"os"
	"os/exec"
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
	return wrapper, append(flags, args...), nil
}
