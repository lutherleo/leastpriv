// Command lp-synth writes the deterministic synthetic scenario (IAM
// inventory, CloudTrail logs and ground truth) used by tests, the demo and
// the evaluation.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/lutherleo/leastpriv/internal/synth"
)

func main() {
	out := flag.String("out", "testdata/acme", "output directory")
	seed := flag.Uint64("seed", synth.DefaultConfig().Seed, "random seed")
	flag.Parse()
	cfg := synth.DefaultConfig()
	cfg.Seed = *seed
	sc, err := synth.Generate(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lp-synth:", err)
		os.Exit(1)
	}
	if err := sc.Write(*out); err != nil {
		fmt.Fprintln(os.Stderr, "lp-synth:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s: %d events in %d log files, %d principals\n", *out, sc.Truth.Events, len(sc.Files), len(sc.Truth.Principals))
}
