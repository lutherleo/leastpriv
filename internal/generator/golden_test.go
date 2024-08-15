package generator

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lutherleo/leastpriv/internal/activity"
	"github.com/lutherleo/leastpriv/internal/authz"
)

var update = flag.Bool("update", false, "rewrite golden files")

// TestGoldenFixtures pins the policies generated from the committed synthetic
// scenario. Run `go test ./internal/generator -run Golden -update` after an
// intentional change and review the diff.
func TestGoldenFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	inv, err := authz.LoadFile(filepath.Join(root, "acme", "authz.json"))
	if err != nil {
		t.Fatal(err)
	}
	ds, err := activity.Load(filepath.Join(root, "acme", "cloudtrail"), cat, activity.Options{Inventory: inv})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range inv.Principals {
		key, _ := authz.Key(p.ARN)
		for _, level := range []Level{LevelModerate, LevelAggressive} {
			res, err := Generate(cat, Input{Principal: p, Observations: ds.ByPrincipal[key]}, Options{Level: level})
			if err != nil {
				t.Fatal(err)
			}
			got := []byte("null\n")
			if res.Policy != nil {
				if got, err = res.Policy.Pretty(); err != nil {
					t.Fatal(err)
				}
			}
			name := strings.ReplaceAll(p.Kind+"-"+p.Name, "/", "_") + "." + string(level) + ".json"
			path := filepath.Join(root, "golden", name)
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(path) // #nosec G304 -- test fixture
			if err != nil {
				t.Fatalf("%v (run with -update to create)", err)
			}
			if string(want) != string(got) {
				t.Errorf("%s differs from golden file; rerun with -update if intended\n--- got ---\n%s", name, got)
			}
		}
	}
}
