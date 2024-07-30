// Command lp-eval scores the generator and the gap report against the
// synthetic scenario's ground truth using a temporal train/test split.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lutherleo/leastpriv/internal/evalharness"
	"github.com/lutherleo/leastpriv/internal/report"
)

func main() {
	dir := flag.String("data", "testdata/acme", "scenario directory (authz.json, truth.json, cloudtrail/)")
	out := flag.String("out", "", "also write results.md and results.json to this directory")
	flag.Parse()
	res, err := evalharness.Run(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lp-eval:", err)
		os.Exit(1)
	}
	if err := res.Markdown(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "lp-eval:", err)
		os.Exit(1)
	}
	if *out == "" {
		return
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		fmt.Fprintln(os.Stderr, "lp-eval:", err)
		os.Exit(1)
	}
	md, err := os.Create(filepath.Join(*out, "results.md"))
	if err == nil {
		err = res.Markdown(md)
		if cerr := md.Close(); err == nil {
			err = cerr
		}
	}
	if err == nil {
		var js *os.File
		js, err = os.Create(filepath.Join(*out, "results.json"))
		if err == nil {
			err = report.WriteJSON(js, res)
			if cerr := js.Close(); err == nil {
				err = cerr
			}
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "lp-eval:", err)
		os.Exit(1)
	}
}
