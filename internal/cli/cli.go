// Package cli implements the leastpriv command-line interface. It is kept
// separate from package main so the commands are unit- and integration-
// testable.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lutherleo/leastpriv/internal/activity"
	"github.com/lutherleo/leastpriv/internal/authz"
	"github.com/lutherleo/leastpriv/internal/catalog"
	"github.com/lutherleo/leastpriv/internal/cloudtrail"
	"github.com/lutherleo/leastpriv/internal/diff"
	"github.com/lutherleo/leastpriv/internal/engine"
	"github.com/lutherleo/leastpriv/internal/gap"
	"github.com/lutherleo/leastpriv/internal/generator"
	"github.com/lutherleo/leastpriv/internal/mapper"
	"github.com/lutherleo/leastpriv/internal/policy"
	"github.com/lutherleo/leastpriv/internal/report"
	"github.com/lutherleo/leastpriv/internal/verify"
)

// Version is the tool version reported by `leastpriv version`.
const Version = "0.1.0"

// Exit codes.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitVerifyFail  = 3
	ExitInvalidPoly = 4
)

const usage = `leastpriv - least-privilege IAM policy generator and right-sizer

Usage:
  leastpriv generate --authz FILE --trail PATH [flags]   generate, verify and diff minimal policies
  leastpriv gap      --authz FILE --trail PATH [flags]   permission-gap report (granted vs used)
  leastpriv verify   --authz FILE --trail PATH --principal ARN --policy FILE
  leastpriv diff     BEFORE.json AFTER.json [--format md|json]
  leastpriv simulate (--policy FILE | --authz FILE --principal ARN) --action A --resource R [--context k=v]...
  leastpriv validate FILE...
  leastpriv catalog  [PATTERN]
  leastpriv map      --trail PATH [--limit N]
  leastpriv version

Run "leastpriv <command> -h" for the flags of a command.
`

type env struct {
	stdout, stderr io.Writer
	log            *slog.Logger
	cat            *catalog.Catalog
}

// Run executes the CLI with args (without the program name) and returns the
// process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	out := &stickyWriter{w: stdout}
	e := &env{stdout: out, stderr: stderr, cat: catalog.Default()}
	e.log = slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cmd, rest := args[0], args[1:]
	var err error
	code := ExitOK
	switch cmd {
	case "generate":
		code, err = e.generate(rest)
	case "gap":
		err = e.gap(rest)
	case "verify":
		code, err = e.verify(rest)
	case "diff":
		err = e.diff(rest)
	case "simulate":
		err = e.simulate(rest)
	case "validate":
		code, err = e.validate(rest)
	case "catalog":
		err = e.catalogCmd(rest)
	case "map":
		err = e.mapCmd(rest)
	case "version", "--version":
		fmt.Fprintf(out, "leastpriv %s (catalog: %d services, %d actions)\n", Version, len(e.cat.Services), len(e.cat.Actions()))
	case "help", "-h", "--help":
		fmt.Fprint(out, usage)
	default:
		fmt.Fprintf(stderr, "leastpriv: unknown command %q\n\n%s", cmd, usage)
		return ExitUsage
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	var ue usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(stderr, "leastpriv %s: %v\n", cmd, err)
		return ExitUsage
	}
	if err == nil && out.err != nil {
		err = fmt.Errorf("writing output: %w", out.err)
	}
	if err != nil {
		fmt.Fprintf(stderr, "leastpriv %s: %v\n", cmd, err)
		return ExitError
	}
	return code
}

// stickyWriter remembers the first write error so that the many unchecked
// fmt.Fprint calls that render reports still turn a failed write (for example
// a full disk or closed pipe) into a non-zero exit code.
type stickyWriter struct {
	w   io.Writer
	err error
}

func (s *stickyWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.w.Write(p)
	if err != nil {
		s.err = err
	}
	return n, err
}

type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func (e *env) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	return fs
}

// parse parses flags, classifying malformed flags as usage errors.
func parse(fs *flag.FlagSet, args []string) error {
	err := fs.Parse(args)
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return err
	}
	return usageError{err.Error()}
}

func (e *env) verbose(v bool) {
	if v {
		e.log = slog.New(slog.NewTextHandler(e.stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, usageError{fmt.Sprintf("bad time %q (want YYYY-MM-DD or RFC 3339)", s)}
	}
	return t, nil
}

// common loads the inventory and activity shared by generate/gap/verify.
type common struct {
	authzPath, trailPath string
	principals           stringList
	from, to             string
	verbose              bool
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.authzPath, "authz", "", "IAM inventory: get-account-authorization-details JSON or a principals bundle (required)")
	fs.StringVar(&c.trailPath, "trail", "", "CloudTrail log file or directory (.json, .jsonl, .json.gz) (required)")
	fs.Var(&c.principals, "principal", "principal ARN to analyse (repeatable; default: all in the inventory)")
	fs.StringVar(&c.from, "from", "", "ignore events before this time (YYYY-MM-DD or RFC 3339)")
	fs.StringVar(&c.to, "to", "", "ignore events at or after this time")
	fs.BoolVar(&c.verbose, "v", false, "verbose logging to stderr")
}

type loaded struct {
	inv        *authz.Inventory
	ds         *activity.Dataset
	principals []*authz.Principal
	from, to   time.Time
}

func (e *env) load(c *common) (*loaded, error) {
	if c.authzPath == "" || c.trailPath == "" {
		return nil, usageError{"--authz and --trail are required"}
	}
	e.verbose(c.verbose)
	inv, err := authz.LoadFile(c.authzPath)
	if err != nil {
		return nil, err
	}
	from, err := parseTime(c.from)
	if err != nil {
		return nil, err
	}
	to, err := parseTime(c.to)
	if err != nil {
		return nil, err
	}
	ds, err := activity.Load(c.trailPath, e.cat, activity.Options{Inventory: inv, From: from, To: to, Logger: e.log})
	if err != nil {
		return nil, err
	}
	e.log.Info("loaded activity", "records", ds.Stats.Records, "observations", ds.Stats.Observations)
	l := &loaded{inv: inv, ds: ds, from: from, to: to}
	if len(c.principals) == 0 {
		l.principals = inv.Principals
	} else {
		for _, a := range c.principals {
			p, ok := inv.Find(a)
			if !ok {
				return nil, fmt.Errorf("principal %s not found in %s", a, c.authzPath)
			}
			l.principals = append(l.principals, p)
		}
	}
	return l, nil
}

func (l *loaded) observations(p *authz.Principal) []activity.Observation {
	k, _ := authz.Key(p.ARN)
	return l.ds.ByPrincipal[k]
}

func (e *env) generate(args []string) (int, error) {
	fs := e.flags("generate")
	var c common
	c.register(fs)
	level := fs.String("level", "moderate", "aggressiveness: exact, moderate or aggressive")
	minSiblings := fs.Int("min-siblings", 0, "resource-collapse threshold (0: level default)")
	minActions := fs.Int("min-actions", 3, "aggressive action-collapse threshold")
	maxSize := fs.Int("max-size", policy.LimitManaged, "split policies larger than this many characters (0: never)")
	out := fs.String("out", "", "directory for generated policies, reports and original/ copies of the input policies")
	format := fs.String("format", "md", "report format on stdout: md or json")
	noVerify := fs.Bool("no-verify", false, "skip verification")
	if err := parse(fs, args); err != nil {
		return ExitUsage, err
	}
	lvl, err := generator.ParseLevel(*level)
	if err != nil {
		return ExitUsage, usageError{err.Error()}
	}
	if *format != "md" && *format != "json" {
		return ExitUsage, usageError{"--format must be md or json"}
	}
	l, err := e.load(&c)
	if err != nil {
		return ExitError, err
	}
	run := &report.Run{Level: lvl, Input: l.ds.Stats}
	code := ExitOK
	for _, p := range l.principals {
		obs := l.observations(p)
		res, err := generator.Generate(e.cat, generator.Input{Principal: p, Observations: obs},
			generator.Options{Level: lvl, MinSiblings: *minSiblings, MinActions: *minActions, MaxSize: *maxSize})
		if err != nil {
			return ExitError, err
		}
		pr := report.PrincipalRun{Generation: res}
		if res.Policy != nil {
			docs := []*policy.Document{res.Policy}
			if len(res.Parts) > 0 {
				docs = res.Parts
			}
			if !*noVerify {
				v, err := verify.Verify(e.cat, p, docs, obs, verify.Options{})
				if err != nil {
					return ExitError, err
				}
				pr.Verify = v
				if !v.OK {
					code = ExitVerifyFail
				}
			}
			d, err := diff.Compare(e.cat, originalDocs(p), docs)
			if err != nil {
				return ExitError, err
			}
			pr.Diff = d
			if *out != "" {
				if err := writePolicies(*out, p, res); err != nil {
					return ExitError, err
				}
			}
		}
		run.Principals = append(run.Principals, pr)
	}
	if *out != "" {
		if err := writeReports(*out, "report", run, func(w io.Writer) error { return report.GenerateMarkdown(w, run) }); err != nil {
			return ExitError, err
		}
	}
	if *format == "json" {
		return code, report.WriteJSON(e.stdout, run)
	}
	return code, report.GenerateMarkdown(e.stdout, run)
}

func originalDocs(p *authz.Principal) []*policy.Document {
	out := make([]*policy.Document, 0, len(p.Policies))
	for _, nd := range p.Policies {
		out = append(out, nd.Doc)
	}
	return out
}

func fileStem(p *authz.Principal) string {
	return p.Kind + "-" + strings.NewReplacer("/", "_", ":", "_").Replace(p.Name)
}

func writePolicies(dir string, p *authz.Principal, res *generator.Result) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	docs := []*policy.Document{res.Policy}
	if len(res.Parts) > 0 {
		docs = res.Parts
	}
	for i, d := range docs {
		name := fileStem(p) + ".policy.json"
		if len(docs) > 1 {
			name = fmt.Sprintf("%s.part%d.policy.json", fileStem(p), i+1)
		}
		b, err := d.Pretty()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return err
		}
	}
	return writeOriginals(filepath.Join(dir, "original"), p)
}

// writeOriginals writes the principal's original identity policies as
// <stem>.<n>.json so a reviewer can run "leastpriv diff" on before/after
// files (pass several documents per side comma-separated).
func writeOriginals(dir string, p *authz.Principal) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	for i, nd := range p.Policies {
		b, err := nd.Doc.Pretty()
		if err != nil {
			return err
		}
		name := fmt.Sprintf("%s.%d.json", fileStem(p), i+1)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// createPrivate creates (or truncates) a report file readable only by the
// operator: reports describe who can do what in the account.
func createPrivate(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- user-chosen output dir
}

func writeReports(dir, stem string, v any, md func(io.Writer) error) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	jf, err := createPrivate(filepath.Join(dir, stem+".json"))
	if err != nil {
		return err
	}
	if err := report.WriteJSON(jf, v); err != nil {
		_ = jf.Close()
		return err
	}
	if err := jf.Close(); err != nil {
		return err
	}
	mf, err := createPrivate(filepath.Join(dir, stem+".md"))
	if err != nil {
		return err
	}
	if err := md(mf); err != nil {
		_ = mf.Close()
		return err
	}
	return mf.Close()
}

func (e *env) gap(args []string) error {
	fs := e.flags("gap")
	var c common
	c.register(fs)
	now := fs.String("now", "", "reference time for last-used ages (default: --to, else the last event)")
	staleDays := fs.Int("stale-days", 30, "flag used actions not seen for this many days as stale")
	format := fs.String("format", "md", "output format: md or json")
	out := fs.String("out", "", "also write gap.md and gap.json to this directory")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *format != "md" && *format != "json" {
		return usageError{"--format must be md or json"}
	}
	nowT, err := parseTime(*now)
	if err != nil {
		return err
	}
	l, err := e.load(&c)
	if err != nil {
		return err
	}
	start, end := l.from, l.to
	if start.IsZero() {
		start = l.ds.Stats.First
	}
	if end.IsZero() {
		end = l.ds.Stats.Last
	}
	var reps []*gap.Report
	for _, p := range l.principals {
		r, err := gap.Analyze(e.cat, p, l.observations(p), gap.Options{Now: nowT, StaleDays: *staleDays, WindowStart: start, WindowEnd: end})
		if err != nil {
			return err
		}
		reps = append(reps, r)
	}
	if *out != "" {
		if err := writeReports(*out, "gap", reps, func(w io.Writer) error { return report.GapMarkdown(w, reps) }); err != nil {
			return err
		}
	}
	if *format == "json" {
		return report.WriteJSON(e.stdout, reps)
	}
	return report.GapMarkdown(e.stdout, reps)
}

func readPolicyFiles(paths []string) ([]*policy.Document, error) {
	var docs []*policy.Document
	for _, p := range paths {
		for _, part := range strings.Split(p, ",") {
			data, err := os.ReadFile(part) // #nosec G304 -- explicit user input
			if err != nil {
				return nil, err
			}
			d, err := policy.Parse(data)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", part, err)
			}
			docs = append(docs, d)
		}
	}
	return docs, nil
}

func (e *env) verify(args []string) (int, error) {
	fs := e.flags("verify")
	var c common
	c.register(fs)
	var policies stringList
	fs.Var(&policies, "policy", "generated policy file (repeatable or comma-separated)")
	format := fs.String("format", "md", "output format: md or json")
	if err := parse(fs, args); err != nil {
		return ExitUsage, err
	}
	if len(c.principals) != 1 || len(policies) == 0 {
		return ExitUsage, usageError{"exactly one --principal and at least one --policy are required"}
	}
	docs, err := readPolicyFiles(policies)
	if err != nil {
		return ExitError, err
	}
	l, err := e.load(&c)
	if err != nil {
		return ExitError, err
	}
	p := l.principals[0]
	v, err := verify.Verify(e.cat, p, docs, l.observations(p), verify.Options{})
	if err != nil {
		return ExitError, err
	}
	code := ExitOK
	if !v.OK {
		code = ExitVerifyFail
	}
	if *format == "json" {
		return code, report.WriteJSON(e.stdout, v)
	}
	status := "PASS"
	if !v.OK {
		status = "FAIL"
	}
	fmt.Fprintf(e.stdout, "%s %s: replay %d/%d allowed (%d uncertain); differential %d requests, %d allowed by generated, %d violations\n",
		status, p.ARN, v.ReplayAllowed, v.Replayed, v.UncertainReplays, v.SubsetChecked, v.GeneratedAllows, len(v.Violations))
	for _, f := range v.Failures {
		fmt.Fprintf(e.stdout, "  replay failure: %s on %s (%s)\n", f.Action, f.Resource, f.Reason)
	}
	for _, x := range v.Violations {
		fmt.Fprintf(e.stdout, "  subset violation: %s on %s (original %s)\n", x.Action, x.Resource, x.Original)
	}
	return code, nil
}

func (e *env) diff(args []string) error {
	fs := e.flags("diff")
	format := fs.String("format", "md", "output format: md or json")
	if err := parse(fs, reorder(args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return usageError{"diff needs exactly two policy files (use commas to pass several documents per side)"}
	}
	before, err := readPolicyFiles([]string{fs.Arg(0)})
	if err != nil {
		return err
	}
	after, err := readPolicyFiles([]string{fs.Arg(1)})
	if err != nil {
		return err
	}
	d, err := diff.Compare(e.cat, before, after)
	if err != nil {
		return err
	}
	if *format == "json" {
		return report.WriteJSON(e.stdout, d)
	}
	return report.DiffMarkdown(e.stdout, d)
}

// reorder moves flags after positional arguments to the front, so
// "diff a.json b.json --format json" works like the flag package expects.
func reorder(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func (e *env) simulate(args []string) error {
	fs := e.flags("simulate")
	var policies, ctx stringList
	fs.Var(&policies, "policy", "identity policy file (repeatable)")
	boundary := fs.String("boundary", "", "permissions boundary policy file")
	authzPath := fs.String("authz", "", "IAM inventory; with --principal, evaluate that principal's attached policies and boundary instead of --policy")
	principal := fs.String("principal", "", "principal ARN in --authz")
	action := fs.String("action", "", "action, e.g. s3:GetObject (required)")
	resource := fs.String("resource", "*", "resource ARN")
	fs.Var(&ctx, "context", "condition context key=value (repeatable; repeat a key for multiple values)")
	format := fs.String("format", "text", "output format: text or json")
	if err := parse(fs, args); err != nil {
		return err
	}
	fromInventory := *authzPath != "" || *principal != ""
	switch {
	case *action == "":
		return usageError{"--action is required"}
	case fromInventory && (*authzPath == "" || *principal == ""):
		return usageError{"--authz and --principal must be used together"}
	case fromInventory && (len(policies) > 0 || *boundary != ""):
		return usageError{"use either --authz/--principal or --policy/--boundary"}
	case !fromInventory && len(policies) == 0:
		return usageError{"--policy (or --authz with --principal) is required"}
	}
	var set *engine.Set
	var err error
	if fromInventory {
		set, err = principalSet(*authzPath, *principal)
	} else {
		set, err = fileSet(policies, *boundary)
	}
	if err != nil {
		return err
	}
	req := engine.NewRequest(*action, *resource)
	values := map[string][]string{}
	for _, kv := range ctx {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return usageError{fmt.Sprintf("bad --context %q (want key=value)", kv)}
		}
		values[strings.ToLower(k)] = append(values[strings.ToLower(k)], v)
	}
	for k, v := range values {
		req.Set(k, v...)
	}
	res := set.Evaluate(req)
	engine.SortRefs(res.Matched)
	if *format == "json" {
		return report.WriteJSON(e.stdout, res)
	}
	fmt.Fprintf(e.stdout, "%s: %s on %s (%s)\n", res.Decision, *action, *resource, res.Reason)
	for _, m := range res.Matched {
		where := m.Policy
		if m.Boundary {
			where += " (boundary)"
		}
		fmt.Fprintf(e.stdout, "  matched %s statement %d %s [%s]\n", where, m.Index, m.Sid, m.Effect)
	}
	return nil
}

func principalSet(authzPath, arn string) (*engine.Set, error) {
	inv, err := authz.LoadFile(authzPath)
	if err != nil {
		return nil, err
	}
	p, ok := inv.Find(arn)
	if !ok {
		return nil, fmt.Errorf("principal %s not found in %s", arn, authzPath)
	}
	return p.PolicySet()
}

func fileSet(policies []string, boundary string) (*engine.Set, error) {
	docs, err := readPolicyFiles(policies)
	if err != nil {
		return nil, err
	}
	set := &engine.Set{}
	for i, d := range docs {
		c, err := engine.Compile(fmt.Sprintf("policy%d", i+1), d)
		if err != nil {
			return nil, err
		}
		set.Identity = append(set.Identity, c)
	}
	if boundary != "" {
		bd, err := readPolicyFiles([]string{boundary})
		if err != nil {
			return nil, err
		}
		c, err := engine.Compile("boundary", bd[0])
		if err != nil {
			return nil, err
		}
		set.Boundary = c
	}
	return set, nil
}

func (e *env) validate(args []string) (int, error) {
	fs := e.flags("validate")
	if err := parse(fs, args); err != nil {
		return ExitUsage, err
	}
	if fs.NArg() == 0 {
		return ExitUsage, usageError{"validate needs at least one policy file"}
	}
	code := ExitOK
	for _, path := range fs.Args() {
		docs, err := readPolicyFiles([]string{path})
		if err != nil {
			fmt.Fprintf(e.stdout, "%s: %v\n", path, err)
			code = ExitInvalidPoly
			continue
		}
		issues := engine.Validate(docs[0])
		if len(issues) == 0 {
			fmt.Fprintf(e.stdout, "%s: ok\n", path)
			continue
		}
		for _, is := range issues {
			fmt.Fprintf(e.stdout, "%s: %s\n", path, is)
		}
		if policy.HasErrors(issues) {
			code = ExitInvalidPoly
		}
	}
	return code, nil
}

func (e *env) catalogCmd(args []string) error {
	fs := e.flags("catalog")
	if err := parse(fs, args); err != nil {
		return err
	}
	pattern := "*"
	if fs.NArg() > 0 {
		pattern = fs.Arg(0)
		if !strings.Contains(pattern, ":") && pattern != "*" {
			pattern += ":*"
		}
	}
	acts := e.cat.Expand(pattern)
	if len(acts) == 0 {
		return fmt.Errorf("no catalog action matches %q", pattern)
	}
	for _, a := range acts {
		var flags []string
		if a.DataEvent {
			flags = append(flags, "data-event")
		}
		if a.NotLogged {
			flags = append(flags, "not-logged")
		}
		if a.NoAuth {
			flags = append(flags, "no-auth")
		}
		res := "*"
		if len(a.Resources) > 0 {
			res = strings.Join(a.Resources, ",")
		}
		fmt.Fprintf(e.stdout, "%-48s %-24s %-28s %s\n", a.FullName(), a.Access, res, strings.Join(flags, ","))
	}
	return nil
}

func (e *env) mapCmd(args []string) error {
	fs := e.flags("map")
	trail := fs.String("trail", "", "CloudTrail log file or directory (required)")
	limit := fs.Int("limit", 20, "maximum records to print (0: all)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *trail == "" {
		return usageError{"--trail is required"}
	}
	m := mapper.New(e.cat)
	n := 0
	unknown := map[string]int{}
	err := cloudtrail.ReadPath(*trail, func(rec cloudtrail.Record) error {
		if *limit > 0 && n >= *limit {
			return cloudtrail.ErrStop
		}
		principal, ok, reason := rec.PrincipalARN()
		if !ok {
			principal = "(" + reason + ")"
		}
		calls, err := m.Map(&rec)
		if errors.Is(err, mapper.ErrUnknownService) {
			unknown[rec.EventSource]++
			return nil
		}
		if err != nil {
			return err
		}
		n++
		status := "ok"
		if rec.ErrorCode != "" {
			status = rec.ErrorCode
		}
		for _, c := range calls {
			fmt.Fprintf(e.stdout, "%s %-40s %-30s %s -> %s %s [%s]\n", rec.EventTime, principal, rec.EventSource+"/"+rec.EventName, status, c.Action, c.Resource, c.Confidence)
		}
		return nil
	})
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(unknown))
	for k := range unknown {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(e.stdout, "skipped %d events from %s (service not in catalog)\n", unknown[k], k)
	}
	return nil
}
