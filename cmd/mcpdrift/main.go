package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/altrudev/MCP-DriftGuard/internal/baseline"
	mdiff "github.com/altrudev/MCP-DriftGuard/internal/diff"
	"github.com/altrudev/MCP-DriftGuard/internal/probe"
	"github.com/altrudev/MCP-DriftGuard/internal/report"
)

var version = "dev"

func main(){ os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args)==0 { usage(); return 3 }
	switch args[0] {
	case "inspect": return inspect(args[1:])
	case "baseline": return createBaseline(args[1:])
	case "verify": return verify(args[1:])
	case "diff": return diffCmd(args[1:])
	case "keygen": return keygen(args[1:])
	case "version","--version","-v": fmt.Println("mcpdrift",version); return 0
	default: fmt.Fprintln(os.Stderr,"unknown command:",args[0]); usage(); return 3
	}
}

func inspect(args []string) int {
	fs:=flag.NewFlagSet("inspect",flag.ContinueOnError)
	format:=fs.String("format","text","text or json")
	if fs.Parse(args)!=nil||fs.NArg()!=1{return 3}
	s,err:=probe.New().Inspect(context.Background(),fs.Arg(0))
	if err!=nil{return failProbe(err)}
	if err:=report.Snapshot(os.Stdout,s,*format);err!=nil{return fail(err,3)}
	return 0
}

func createBaseline(args []string) int {
	fs:=flag.NewFlagSet("baseline",flag.ContinueOnError)
	out:=fs.String("output","mcpdrift.baseline.json","baseline output path")
	sign:=fs.String("sign-key","","Ed25519 private key PEM")
	if fs.Parse(args)!=nil||fs.NArg()!=1{return 3}
	s,err:=probe.New().Inspect(context.Background(),fs.Arg(0))
	if err!=nil{return failProbe(err)}
	priv,err:=baseline.LoadPrivateKey(*sign);if err!=nil{return fail(err,4)}
	a,err:=baseline.New(s,priv);if err!=nil{return fail(err,4)}
	if err:=baseline.Save(*out,a);err!=nil{return fail(err,4)}
	fmt.Printf("Baseline written: %s\nFingerprint: %s\n",*out,a.CanonicalHash)
	return 0
}

func verify(args []string) int {
	fs:=flag.NewFlagSet("verify",flag.ContinueOnError)
	base:=fs.String("baseline","mcpdrift.baseline.json","baseline path")
	pubPath:=fs.String("verify-key","","Ed25519 public key PEM")
	format:=fs.String("format","text","text or json")
	if fs.Parse(args)!=nil||fs.NArg()!=1{return 3}
	a,err:=baseline.Load(*base);if err!=nil{return fail(err,4)}
	pub,err:=baseline.LoadPublicKey(*pubPath);if err!=nil{return fail(err,4)}
	if err:=a.Validate(pub);err!=nil{return fail(err,5)}
	live,err:=probe.New().Inspect(context.Background(),fs.Arg(0));if err!=nil{return failProbe(err)}
	r:=mdiff.Compare(a.Snapshot,live)
	if err:=report.Diff(os.Stdout,r,*format);err!=nil{return fail(err,3)}
	if r.Match{return 0};if r.Score>=35{return 2};return 1
}

func diffCmd(args []string) int {
	fs:=flag.NewFlagSet("diff",flag.ContinueOnError)
	format:=fs.String("format","text","text or json")
	if fs.Parse(args)!=nil||fs.NArg()!=2{return 3}
	a,err:=baseline.Load(fs.Arg(0));if err!=nil{return fail(err,4)}
	b,err:=baseline.Load(fs.Arg(1));if err!=nil{return fail(err,4)}
	r:=mdiff.Compare(a.Snapshot,b.Snapshot)
	if err:=report.Diff(os.Stdout,r,*format);err!=nil{return fail(err,3)}
	if r.Match{return 0};if r.Score>=35{return 2};return 1
}

func keygen(args []string) int {
	fs:=flag.NewFlagSet("keygen",flag.ContinueOnError)
	priv:=fs.String("private","mcpdrift.ed25519.pem","private key output")
	pub:=fs.String("public","mcpdrift.ed25519.pub.pem","public key output")
	if fs.Parse(args)!=nil{return 3}
	if err:=baseline.GenerateKeyPair(*priv,*pub);err!=nil{return fail(err,4)}
	fmt.Printf("Private key: %s\nPublic key: %s\n",*priv,*pub)
	return 0
}

func failProbe(err error) int{return fail(err,3)}
func fail(err error,code int) int{fmt.Fprintln(os.Stderr,"mcpdrift:",err);return code}
func usage(){fmt.Fprintln(os.Stderr,"Usage: mcpdrift <inspect|baseline|verify|diff|keygen|version> [options]")}
