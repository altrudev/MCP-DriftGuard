//go:build !linux

package observe

import (
	"errors"
	"os"
)

func stdioSandboxCommand(target string, args []string) (string, []string, error) {
	if os.Getenv("MCPDRIFT_STDIO_SANDBOX") != "" {
		return "", nil, errors.New("stdio sandbox unavailable on this platform")
	}
	return target, args, nil
}
