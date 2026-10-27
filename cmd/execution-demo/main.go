// execution-demo never connects to operator-selected endpoints.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/altrudev/MCP-DriftGuard/internal/executiondemo"
	"os"
)

func main() {
	confirm := flag.String("confirm", "", "required: execute-local-mock-only")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "no positional arguments accepted")
		os.Exit(2)
	}
	a, e := executiondemo.Run(*confirm)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if e = json.NewEncoder(os.Stdout).Encode(a); e != nil {
		os.Exit(1)
	}
}
