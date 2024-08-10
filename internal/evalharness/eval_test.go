package evalharness

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunOnFixtures(t *testing.T) {
	res, err := Run(filepath.Join("..", "..", "testdata", "acme"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 15 || len(res.Gap) != 5 {
		t.Fatalf("rows %d gap %d", len(res.Rows), len(res.Gap))
	}
	byKey := map[string]Row{}
	for _, r := range res.Rows {
		byKey[r.Principal+"|"+r.Level] = r
		if !r.VerificationPassed {
			t.Errorf("%s %s: training replay failed", r.Principal, r.Level)
		}
		if r.ExcessGenerated > r.ExcessOriginal || r.DecoysGenerated > r.DecoysOriginal {
			t.Errorf("%s %s: generated policy is broader than the original", r.Principal, r.Level)
		}
	}
	app := "arn:aws:iam::111122223333:role/app/app-backend"
	if !(byKey[app+"|aggressive"].HeldOutAllowRate >= byKey[app+"|moderate"].HeldOutAllowRate &&
		byKey[app+"|moderate"].HeldOutAllowRate >= byKey[app+"|exact"].HeldOutAllowRate) {
		t.Fatal("held-out allow rate must be monotone in aggressiveness for app-backend")
	}
	for _, g := range res.Gap {
		if g.Precision < 0.9 || g.Recall < 0.9 {
			t.Errorf("gap score too low: %+v", g)
		}
	}
	var b bytes.Buffer
	if err := res.Markdown(&b); err != nil || !strings.Contains(b.String(), "| role/app/app-backend | moderate |") {
		t.Fatalf("markdown: %v\n%s", err, b.String())
	}
	if _, err := Run(t.TempDir()); err == nil {
		t.Fatal("missing data must error")
	}
	if short("arn:aws:iam::1:root") != "arn:aws:iam::1:root" || ratio(1, 0) != 1 {
		t.Fatal("helpers")
	}
}
