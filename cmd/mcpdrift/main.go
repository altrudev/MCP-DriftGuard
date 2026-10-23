package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/altrudev/MCP-DriftGuard/internal/baseline"
	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
	mdiff "github.com/altrudev/MCP-DriftGuard/internal/diff"
	"github.com/altrudev/MCP-DriftGuard/internal/mcpserver"
	"github.com/altrudev/MCP-DriftGuard/internal/observe"
	"github.com/altrudev/MCP-DriftGuard/internal/report"
)

var version = "dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 3
	}
	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "inspect":
		return inspect(args[1:])
	case "baseline":
		return createBaseline(args[1:])
	case "verify":
		return verify(args[1:])
	case "diff":
		return diffCmd(args[1:])
	case "keygen":
		return keygen(args[1:])
	case "version", "--version", "-v":
		fmt.Println("mcpdrift", version)
		return 0
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", args[0])
		usage()
		return 3
	}
}

func inspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	format := fs.String("format", "text", "text, json, or sarif")
	stdioExecutable := fs.String("stdio-exec", "", "approved absolute MCP stdio server executable")
	stdioArgs := fs.String("stdio-args-json", "[]", "trusted JSON array of stdio server arguments")
	if parseOneEndpoint(fs, args) != nil || fs.NArg() != 1 {
		return 3
	}
	s, err := inspectTarget(fs.Arg(0), *stdioExecutable, *stdioArgs)
	if err != nil {
		return failProbe(err)
	}
	if err := report.Snapshot(os.Stdout, s, *format); err != nil {
		return fail(err, 3)
	}
	return 0
}

func createBaseline(args []string) int {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	out := fs.String("output", "mcpdrift.baseline.json", "baseline output path")
	sign := fs.String("sign-key", "", "Ed25519 private key PEM")
	stdioExecutable := fs.String("stdio-exec", "", "approved absolute MCP stdio server executable")
	stdioArgs := fs.String("stdio-args-json", "[]", "trusted JSON array of stdio server arguments")
	if parseOneEndpoint(fs, args) != nil || fs.NArg() != 1 {
		return 3
	}
	s, err := inspectTarget(fs.Arg(0), *stdioExecutable, *stdioArgs)
	if err != nil {
		return failProbe(err)
	}
	priv, err := baseline.LoadPrivateKey(*sign)
	if err != nil {
		return fail(err, 4)
	}
	a, err := baseline.New(s, priv)
	if err != nil {
		return fail(err, 4)
	}
	if err := baseline.Save(*out, a); err != nil {
		return fail(err, 4)
	}
	fmt.Printf("Baseline written: %s\nFingerprint: %s\n", *out, a.CanonicalHash)
	return 0
}

func verify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	base := fs.String("baseline", "mcpdrift.baseline.json", "baseline path")
	pubPath := fs.String("verify-key", "", "Ed25519 public key PEM")
	stdioExecutable := fs.String("stdio-exec", "", "approved absolute MCP stdio server executable")
	stdioArgs := fs.String("stdio-args-json", "[]", "trusted JSON array of stdio server arguments")
	format := fs.String("format", "text", "text, json, or sarif")
	if parseOneEndpoint(fs, args) != nil || fs.NArg() != 1 {
		return 3
	}
	a, err := baseline.Load(*base)
	if err != nil {
		return fail(err, 4)
	}
	pub, err := baseline.LoadPublicKey(*pubPath)
	if err != nil {
		return fail(err, 4)
	}
	if err := a.Validate(pub); err != nil {
		return fail(err, 5)
	}
	live, err := inspectTarget(fs.Arg(0), *stdioExecutable, *stdioArgs)
	if err != nil {
		return failProbe(err)
	}
	r := mdiff.Compare(a.Snapshot, live)
	if err := report.Diff(os.Stdout, r, *format); err != nil {
		return fail(err, 3)
	}
	if r.Match {
		return 0
	}
	if r.Score >= 35 {
		return 2
	}
	return 1
}

func diffCmd(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	format := fs.String("format", "text", "text, json, or sarif")
	if fs.Parse(args) != nil || fs.NArg() != 2 {
		return 3
	}
	a, err := baseline.Load(fs.Arg(0))
	if err != nil {
		return fail(err, 4)
	}
	b, err := baseline.Load(fs.Arg(1))
	if err != nil {
		return fail(err, 4)
	}
	r := mdiff.Compare(a.Snapshot, b.Snapshot)
	if err := report.Diff(os.Stdout, r, *format); err != nil {
		return fail(err, 3)
	}
	if r.Match {
		return 0
	}
	if r.Score >= 35 {
		return 2
	}
	return 1
}

func keygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	priv := fs.String("private", "mcpdrift.ed25519.pem", "private key output")
	pub := fs.String("public", "mcpdrift.ed25519.pub.pem", "public key output")
	if fs.Parse(args) != nil {
		return 3
	}
	if err := baseline.GenerateKeyPair(*priv, *pub); err != nil {
		return fail(err, 4)
	}
	fmt.Printf("Private key: %s\nPublic key: %s\n", *priv, *pub)
	return 0
}

func parseOneEndpoint(fs *flag.FlagSet, args []string) error {
	if len(args) > 1 && !strings.HasPrefix(args[0], "-") {
		args = append(append([]string{}, args[1:]...), args[0])
	}
	return fs.Parse(args)
}

func failProbe(err error) int      { return fail(err, 3) }
func fail(err error, code int) int { fmt.Fprintln(os.Stderr, "mcpdrift:", err); return code }
func usage() {
	fmt.Fprintln(os.Stderr, "Usage: mcpdrift <serve|inspect|baseline|verify|diff|keygen|version> [options]")
}

func inspectTarget(endpoint, executable, argsJSON string) (canonical.Snapshot, error) {
	return inspectTargetContext(context.Background(), endpoint, executable, argsJSON)
}

func inspectTargetContext(ctx context.Context, endpoint, executable, argsJSON string) (canonical.Snapshot, error) {
	if executable == "" {
		if endpoint == "stdio" {
			return canonical.Snapshot{}, errors.New("stdio endpoint requires --stdio-exec")
		}
		return observe.New().Inspect(ctx, endpoint)
	}
	if endpoint != "stdio" {
		return canonical.Snapshot{}, errors.New("stdio executable requires explicit stdio endpoint")
	}
	var args []string
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return canonical.Snapshot{}, fmt.Errorf("stdio args must be JSON array: %w", err)
	}
	return observe.InspectStdio(ctx, executable, args)
}

// serve binds probe authority to startup configuration, never tool arguments.
func serve(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	endpoint := fs.String("endpoint", "", "operator-authorized endpoint (required)")
	path := fs.String("baseline", "", "approved baseline path (required)")
	key := fs.String("verify-key", "", "trusted Ed25519 public key PEM (required)")
	executable := fs.String("stdio-exec", "", "approved stdio executable")
	argv := fs.String("stdio-args-json", "[]", "approved stdio argument vector")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *endpoint == "" || *path == "" || *key == "" {
		return fail(errors.New("serve requires --endpoint, --baseline and --verify-key"), 3)
	}
	pub, err := baseline.LoadPublicKey(*key)
	if err != nil {
		return fail(err, 4)
	}
	approved, err := baseline.Load(*path)
	if err != nil {
		return fail(err, 4)
	}
	if err = approved.Validate(pub); err != nil {
		return fail(err, 5)
	}
	// Pin the validated artifact in memory for this session. Replacement on disk
	// cannot silently change which baseline a running agent trusts.
	call := func(name string) (any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		live, err := inspectTargetContext(ctx, *endpoint, *executable, *argv)
		if err != nil {
			return nil, err
		}
		if name == "driftguard_inspect" {
			return live, nil
		}
		return mdiff.Compare(approved.Snapshot, live), nil
	}
	if err = mcpserver.Serve(os.Stdin, os.Stdout, version, call); err != nil {
		return fail(err, 3)
	}
	return 0
}
