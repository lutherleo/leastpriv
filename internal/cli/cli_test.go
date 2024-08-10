package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	authzPath = filepath.Join("..", "..", "testdata", "acme", "authz.json")
	trailPath = filepath.Join("..", "..", "testdata", "acme", "cloudtrail")
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGenerateEndToEnd(t *testing.T) {
	out := t.TempDir()
	code, stdout, stderr := run(t, "generate", "--authz", authzPath, "--trail", trailPath, "--out", out, "--level", "moderate")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{"# Least-privilege policy report", "Verification: **PASS**", "role/app/app-backend", "No policy generated."} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q", want)
		}
	}
	for _, f := range []string{"role-app-backend.policy.json", "role-ci-deployer.policy.json", "user-analyst-01.policy.json", "report.md", "report.json", "original/role-ci-deployer.1.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("missing output %s", f)
		}
	}
	var rep struct {
		Principals []struct {
			Verification *struct{ OK bool } `json:"verification"`
		} `json:"principals"`
	}
	b, _ := os.ReadFile(filepath.Join(out, "report.json"))
	if err := json.Unmarshal(b, &rep); err != nil || len(rep.Principals) != 5 {
		t.Fatalf("report.json: %v", err)
	}
	// The generated policy verifies through the verify subcommand too.
	code, stdout, _ = run(t, "verify", "--authz", authzPath, "--trail", trailPath, "--principal", "arn:aws:iam::111122223333:role/app/app-backend",
		"--policy", filepath.Join(out, "role-app-backend.policy.json"))
	if code != ExitOK || !strings.HasPrefix(stdout, "PASS") {
		t.Fatalf("verify: %d %s", code, stdout)
	}
	// And diffs against itself as unchanged.
	p := filepath.Join(out, "role-ops-automation.policy.json")
	code, stdout, _ = run(t, "diff", p, p, "--format", "json")
	if code != ExitOK || !strings.Contains(stdout, `"unified": ""`) {
		t.Fatalf("self diff: %s", stdout)
	}
	// The exported original diffs against the generated policy: only narrowing.
	code, stdout, _ = run(t, "diff", filepath.Join(out, "original", "role-ci-deployer.1.json"), filepath.Join(out, "role-ci-deployer.policy.json"))
	if code != ExitOK || !strings.Contains(stdout, "| 200 | 8 | 0 | 0 | 0 | 0 |") {
		t.Fatalf("original vs generated diff: %s", stdout)
	}
	code, stdout, _ = run(t, "validate", p)
	if code != ExitOK || !strings.Contains(stdout, ": ok") {
		t.Fatalf("validate: %s", stdout)
	}
}

func TestGenerateJSONAndOptions(t *testing.T) {
	code, stdout, stderr := run(t, "generate", "--authz", authzPath, "--trail", trailPath, "--format", "json", "--level", "aggressive",
		"--principal", "arn:aws:iam::111122223333:role/ops-automation", "--to", "2026-08-01", "--max-size", "400", "-v")
	if code != ExitOK {
		t.Fatalf("exit %d %s", code, stderr)
	}
	var run struct {
		Principals []struct {
			Generation struct {
				Parts      []json.RawMessage `json:"parts"`
				Expansions []json.RawMessage `json:"expansions"`
			} `json:"generation"`
		} `json:"principals"`
	}
	if err := json.Unmarshal([]byte(stdout), &run); err != nil {
		t.Fatal(err)
	}
	if len(run.Principals) != 1 || len(run.Principals[0].Generation.Parts) < 2 || len(run.Principals[0].Generation.Expansions) != 1 {
		t.Fatalf("unexpected run: %s", stdout)
	}
	if !strings.Contains(stderr, "level=INFO") {
		t.Fatal("verbose logging")
	}
}

func TestGapCommand(t *testing.T) {
	out := t.TempDir()
	code, stdout, _ := run(t, "gap", "--authz", authzPath, "--trail", trailPath, "--stale-days", "14", "--out", out)
	if code != ExitOK || !strings.Contains(stdout, "# Permission gap report") || !strings.Contains(stdout, "iam:PassRole") {
		t.Fatalf("gap md: %d", code)
	}
	if _, err := os.Stat(filepath.Join(out, "gap.json")); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ = run(t, "gap", "--authz", authzPath, "--trail", trailPath, "--format", "json", "--now", "2026-10-01T00:00:00Z",
		"--principal", "arn:aws:iam::111122223333:role/legacy-reporting", "--from", "2026-07-01")
	var reps []struct {
		Unused int `json:"unused"`
		Used   int `json:"used"`
	}
	if code != ExitOK || json.Unmarshal([]byte(stdout), &reps) != nil || len(reps) != 1 || reps[0].Used != 0 || reps[0].Unused == 0 {
		t.Fatalf("gap json: %s", stdout)
	}
}

func TestSimulateValidateCatalogMap(t *testing.T) {
	dir := t.TempDir()
	pol := writeFile(t, dir, "p.json", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"StringEquals":{"aws:RequestedRegion":["us-east-1"]}}}]}`)
	bnd := writeFile(t, dir, "b.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
	code, stdout, _ := run(t, "simulate", "--policy", pol, "--boundary", bnd, "--action", "s3:GetObject", "--resource", "arn:aws:s3:::b/k", "--context", "aws:RequestedRegion=us-east-1")
	if code != ExitOK || !strings.HasPrefix(stdout, "allowed") || !strings.Contains(stdout, "(boundary)") {
		t.Fatalf("simulate: %s", stdout)
	}
	code, stdout, _ = run(t, "simulate", "--policy", pol, "--action", "s3:GetObject", "--resource", "arn:aws:s3:::b/k", "--format", "json")
	if code != ExitOK || !strings.Contains(stdout, `"decision": "implicitDeny"`) {
		t.Fatalf("simulate json: %s", stdout)
	}
	if code, _, _ = run(t, "simulate", "--policy", pol, "--action", "s3:GetObject", "--context", "novalue"); code != ExitUsage {
		t.Fatal("bad context must be a usage error")
	}
	bad := writeFile(t, dir, "bad.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject"}]}`)
	warn := writeFile(t, dir, "warn.json", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	broken := writeFile(t, dir, "broken.json", `{`)
	code, stdout, _ = run(t, "validate", bad, warn, broken)
	if code != ExitInvalidPoly || !strings.Contains(stdout, "missing-resource") || !strings.Contains(stdout, "full-admin") || !strings.Contains(stdout, "broken.json:") {
		t.Fatalf("validate: %d %s", code, stdout)
	}
	code, stdout, _ = run(t, "catalog", "sts")
	if code != ExitOK || !strings.Contains(stdout, "sts:GetCallerIdentity") || !strings.Contains(stdout, "no-auth") {
		t.Fatalf("catalog: %s", stdout)
	}
	code, stdout, _ = run(t, "catalog")
	if code != ExitOK || strings.Count(stdout, "\n") < 150 || !strings.Contains(stdout, "not-logged") || !strings.Contains(stdout, "data-event") {
		t.Fatal("catalog all")
	}
	if code, _, _ = run(t, "catalog", "nosuch:*"); code != ExitError {
		t.Fatal("unknown catalog pattern")
	}
	code, stdout, _ = run(t, "map", "--trail", trailPath, "--limit", "5")
	if code != ExitOK || strings.Count(stdout, "->") < 5 {
		t.Fatalf("map: %s", stdout)
	}
	code, stdout, _ = run(t, "map", "--trail", filepath.Join(trailPath, "us-east-1", "2026-07-01.json.gz"), "--limit", "0")
	if code != ExitOK || !strings.Contains(stdout, "skipped 1 events from cloudformation.amazonaws.com") {
		t.Fatalf("map full: %s", stdout[:min(len(stdout), 400)])
	}
	code, stdout, _ = run(t, "map", "--trail", filepath.Join(trailPath, "us-east-1", "2026-07-02.json.gz"), "--limit", "0")
	if code != ExitOK || !strings.Contains(stdout, "(call made by an AWS service principal)") {
		t.Fatalf("map service principal: %s", stdout[:min(len(stdout), 400)])
	}
}

func TestDiffCommand(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
	b := writeFile(t, dir, "b.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`)
	code, stdout, _ := run(t, "diff", "--format", "md", a, b)
	if code != ExitOK || !strings.Contains(stdout, "**narrowed** `s3:GetObject`") || !strings.Contains(stdout, "**removed**") || !strings.Contains(stdout, "```diff") {
		t.Fatalf("diff: %s", stdout)
	}
	code, _, _ = run(t, "diff", a+","+b, b)
	if code != ExitOK {
		t.Fatal("multi-document side")
	}
}

func TestUsageAndErrors(t *testing.T) {
	cases := []struct {
		args []string
		code int
	}{
		{nil, ExitUsage},
		{[]string{"bogus"}, ExitUsage},
		{[]string{"help"}, ExitOK},
		{[]string{"version"}, ExitOK},
		{[]string{"generate", "-h"}, ExitOK},
		{[]string{"generate"}, ExitUsage},
		{[]string{"generate", "--authz", authzPath, "--trail", trailPath, "--level", "loose"}, ExitUsage},
		{[]string{"generate", "--authz", authzPath, "--trail", trailPath, "--format", "xml"}, ExitUsage},
		{[]string{"generate", "--authz", authzPath, "--trail", trailPath, "--from", "yesterday"}, ExitUsage},
		{[]string{"generate", "--authz", authzPath, "--trail", trailPath, "--to", "nope"}, ExitUsage},
		{[]string{"generate", "--authz", authzPath, "--trail", trailPath, "--principal", "arn:aws:iam::1:role/missing"}, ExitError},
		{[]string{"generate", "--authz", "missing.json", "--trail", trailPath}, ExitError},
		{[]string{"generate", "--nope"}, ExitUsage},
		{[]string{"gap", "--authz", authzPath}, ExitUsage},
		{[]string{"gap", "--authz", authzPath, "--trail", trailPath, "--format", "xml"}, ExitUsage},
		{[]string{"gap", "--authz", authzPath, "--trail", trailPath, "--now", "x"}, ExitUsage},
		{[]string{"gap", "--authz", authzPath, "--trail", "missing"}, ExitError},
		{[]string{"verify", "--authz", authzPath, "--trail", trailPath}, ExitUsage},
		{[]string{"verify", "--authz", authzPath, "--trail", trailPath, "--principal", "x", "--policy", "missing.json"}, ExitError},
		{[]string{"diff", "one.json"}, ExitUsage},
		{[]string{"diff", "missing1.json", "missing2.json"}, ExitError},
		{[]string{"simulate", "--action", "s3:GetObject"}, ExitUsage},
		{[]string{"simulate", "--policy", "missing.json", "--action", "s3:GetObject"}, ExitError},
		{[]string{"validate"}, ExitUsage},
		{[]string{"map"}, ExitUsage},
		{[]string{"map", "--trail", "missing"}, ExitError},
	}
	for _, c := range cases {
		code, _, stderr := run(t, c.args...)
		if code != c.code {
			t.Errorf("%v: exit %d want %d (%s)", c.args, code, c.code, stderr)
		}
	}
}

func TestVerifyFailureExitCode(t *testing.T) {
	dir := t.TempDir()
	tooNarrow := writeFile(t, dir, "narrow.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}`)
	code, stdout, _ := run(t, "verify", "--authz", authzPath, "--trail", trailPath, "--principal", "arn:aws:iam::111122223333:role/ops-automation", "--policy", tooNarrow)
	if code != ExitVerifyFail || !strings.HasPrefix(stdout, "FAIL") || !strings.Contains(stdout, "replay failure") {
		t.Fatalf("verify failure: %d %s", code, stdout)
	}
	tooWide := writeFile(t, dir, "wide.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	code, stdout, _ = run(t, "verify", "--authz", authzPath, "--trail", trailPath, "--principal", "arn:aws:iam::111122223333:role/ops-automation", "--policy", tooWide, "--format", "json")
	if code != ExitVerifyFail || !strings.Contains(stdout, `"violations"`) {
		t.Fatalf("verify violation: %d", code)
	}
	code, stdout, _ = run(t, "verify", "--authz", authzPath, "--trail", trailPath, "--principal", "arn:aws:iam::111122223333:role/ops-automation", "--policy", tooWide)
	if code != ExitVerifyFail || !strings.Contains(stdout, "subset violation") {
		t.Fatalf("verify violation text: %d", code)
	}
}

func TestReorder(t *testing.T) {
	got := strings.Join(reorder([]string{"a", "--format", "json", "b", "-x=1", "-"}), " ")
	if got != "--format json -x=1 a b -" {
		t.Fatalf("reorder: %s", got)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestOutputWriteFailureIsAnError(t *testing.T) {
	var errb bytes.Buffer
	if code := Run([]string{"catalog", "sts"}, failingWriter{}, &errb); code != ExitError {
		t.Fatalf("exit %d, want %d", code, ExitError)
	}
	if !strings.Contains(errb.String(), "writing output") {
		t.Fatalf("stderr %q does not mention the write failure", errb.String())
	}
}

func TestSimulateFromInventory(t *testing.T) {
	app := "arn:aws:iam::111122223333:role/app/app-backend"
	// A decoy the original (over-broad) policy allows.
	code, stdout, stderr := run(t, "simulate", "--authz", authzPath, "--principal", app,
		"--action", "s3:GetObject", "--resource", "arn:aws:s3:::acme-app-data/admin/break-glass.txt")
	if code != ExitOK || !strings.HasPrefix(stdout, "allowed:") {
		t.Fatalf("exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	// The boundary of ops-automation blocks IAM even though identity allows it.
	code, stdout, _ = run(t, "simulate", "--authz", authzPath, "--principal", "arn:aws:iam::111122223333:role/ops-automation",
		"--action", "iam:CreateUser", "--resource", "arn:aws:iam::111122223333:user/x")
	if code != ExitOK || strings.HasPrefix(stdout, "allowed:") {
		t.Fatalf("boundary should block iam:CreateUser: %q", stdout)
	}
	for _, args := range [][]string{
		{"simulate", "--authz", authzPath, "--action", "s3:GetObject"},
		{"simulate", "--authz", authzPath, "--principal", app, "--policy", "x.json", "--action", "s3:GetObject"},
		{"simulate", "--authz", authzPath, "--principal", app},
	} {
		if code, _, _ := run(t, args...); code != ExitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, ExitUsage)
		}
	}
	if code, _, _ := run(t, "simulate", "--authz", authzPath, "--principal", "arn:aws:iam::1:role/none", "--action", "s3:GetObject"); code != ExitError {
		t.Errorf("unknown principal: exit %d", code)
	}
	if code, _, _ := run(t, "simulate", "--authz", "missing.json", "--principal", app, "--action", "s3:GetObject"); code != ExitError {
		t.Errorf("missing inventory: exit %d", code)
	}
}
