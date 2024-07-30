// Command leastpriv generates least-privilege IAM policies from CloudTrail
// activity, verifies them against the original policies, and reports unused
// permissions. See README.md.
package main

import (
	"os"

	"github.com/lutherleo/leastpriv/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
