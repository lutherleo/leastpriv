package synth

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lutherleo/leastpriv/internal/authz"
)

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCommittedFixturesAreReproducible regenerates the scenario and compares
// it with testdata/acme byte for byte (log files after decompression, so a
// different gzip implementation cannot cause false failures).
func TestCommittedFixturesAreReproducible(t *testing.T) {
	sc, err := Generate(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := sc.Write(dir); err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join("..", "..", "testdata", "acme")
	var files []string
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			files = append(files, rel)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 100 {
		t.Fatalf("too few files: %d", len(files))
	}
	for _, rel := range files {
		got, _ := os.ReadFile(filepath.Join(dir, rel))          // #nosec G304 -- test temp dir
		want, err := os.ReadFile(filepath.Join(committed, rel)) // #nosec G304 -- test fixture
		if err != nil {
			t.Fatalf("committed fixture missing %s (run make fixtures): %v", rel, err)
		}
		if filepath.Ext(rel) == ".gz" {
			got, want = gunzip(t, got), gunzip(t, want)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s differs from the committed fixture; run make fixtures", rel)
		}
	}
}

func TestScenarioShape(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Days, cfg.TrainDays = 10, 7
	a, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Generate(cfg)
	if a.Truth.Events != b.Truth.Events || len(a.Files) != len(b.Files) {
		t.Fatal("generation is not deterministic")
	}
	if a.Truth.Events == 0 || len(a.Truth.Principals) != 5 || !a.Truth.TrainEnd.Equal(cfg.Start.AddDate(0, 0, 7)) {
		t.Fatalf("truth %+v", a.Truth)
	}
	inv, err := authz.Parse(a.Authz)
	if err != nil {
		t.Fatal(err)
	}
	for _, pt := range a.Truth.Principals {
		if _, ok := inv.Find(pt.ARN); !ok {
			t.Fatalf("truth principal %s missing from inventory", pt.ARN)
		}
		if len(pt.Decoys) == 0 {
			t.Fatalf("%s has no decoys", pt.ARN)
		}
	}
	legacy, _ := inv.Find("arn:aws:iam::111122223333:role/legacy-reporting")
	if len(legacy.Policies) != 1 || len(legacy.Policies[0].Doc.Statement) != 2 {
		t.Fatal("URL-encoded inline policy must decode")
	}
	cfg.Seed++
	c, _ := Generate(cfg)
	if c.Truth.Events == a.Truth.Events && c.Truth.Noise["uncatalogued-service"] == a.Truth.Noise["uncatalogued-service"] {
		// Event counts can coincide by chance; the bytes must still differ.
		x, _ := EncodeLogFile(c.Files["cloudtrail/us-east-1/2026-07-01.json.gz"])
		y, _ := EncodeLogFile(a.Files["cloudtrail/us-east-1/2026-07-01.json.gz"])
		if bytes.Equal(x, y) {
			t.Fatal("seed has no effect")
		}
	}
	bad := Config{Seed: 1, Start: time.Now(), Days: 5, TrainDays: 5}
	if _, err := Generate(bad); err == nil {
		t.Fatal("invalid config accepted")
	}
	if err := a.Write(filepath.Join(t.TempDir(), "nested", "out")); err != nil {
		t.Fatal(err)
	}
}
