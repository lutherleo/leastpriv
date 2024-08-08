package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// Severity of a validation finding.
type Severity string

// Severities.
const (
	SevError   Severity = "error"
	SevWarning Severity = "warning"
)

// Issue is one validation finding.
type Issue struct {
	Severity  Severity `json:"severity"`
	Statement int      `json:"statement"` // -1 for document-level issues
	Code      string   `json:"code"`
	Message   string   `json:"message"`
}

func (i Issue) String() string {
	loc := "document"
	if i.Statement >= 0 {
		loc = fmt.Sprintf("statement %d", i.Statement)
	}
	return fmt.Sprintf("%s: %s [%s] %s", i.Severity, loc, i.Code, i.Message)
}

// IAM quota limits on policy size (characters, whitespace excluded).
const (
	LimitManaged    = 6144
	LimitRoleInline = 10240
	LimitUserInline = 2048
)

var (
	sidRe    = regexp.MustCompile(`^[A-Za-z0-9]*$`)
	actionRe = regexp.MustCompile(`^[A-Za-z0-9-]+:[A-Za-z0-9*?]+$`)
)

// Validate checks an identity-based policy document against the IAM grammar.
// knownOperator, when non-nil, reports whether a condition operator (with
// optional ForAllValues:/ForAnyValue: prefix and IfExists suffix) is
// supported; the evaluation engine supplies it so the operator list lives in
// one place.
func Validate(d *Document, knownOperator func(string) bool) []Issue {
	var out []Issue
	add := func(sev Severity, st int, code, format string, args ...any) {
		out = append(out, Issue{Severity: sev, Statement: st, Code: code, Message: fmt.Sprintf(format, args...)})
	}
	switch d.Version {
	case Version2012:
	case Version2008:
		add(SevWarning, -1, "old-version", "Version 2008-10-17 disables policy variables; use 2012-10-17")
	case "":
		add(SevWarning, -1, "missing-version", "no Version element; IAM treats this as 2008-10-17 (policy variables are literal text)")
	default:
		add(SevError, -1, "bad-version", "unsupported Version %q", d.Version)
	}
	if len(d.Statement) == 0 {
		add(SevError, -1, "no-statements", "policy has no statements")
	}
	sids := map[string]int{}
	for i := range d.Statement {
		st := &d.Statement[i]
		if st.Sid != "" {
			if !sidRe.MatchString(st.Sid) {
				add(SevError, i, "bad-sid", "Sid %q must contain only ASCII letters and digits", st.Sid)
			}
			if prev, dup := sids[st.Sid]; dup {
				add(SevError, i, "duplicate-sid", "Sid %q already used by statement %d", st.Sid, prev)
			}
			sids[st.Sid] = i
		}
		if st.Effect != Allow && st.Effect != Deny {
			add(SevError, i, "bad-effect", "Effect must be \"Allow\" or \"Deny\", got %q", st.Effect)
		}
		if st.Has("Principal") {
			add(SevError, i, "principal-in-identity-policy", "identity-based policies must not contain Principal/NotPrincipal")
		}
		hasA, hasNA := st.Has("Action"), st.Has("NotAction")
		switch {
		case hasA && hasNA:
			add(SevError, i, "action-and-notaction", "a statement cannot contain both Action and NotAction")
		case !hasA && !hasNA:
			add(SevError, i, "missing-action", "a statement must contain Action or NotAction")
		}
		hasR, hasNR := st.Has("Resource"), st.Has("NotResource")
		switch {
		case hasR && hasNR:
			add(SevError, i, "resource-and-notresource", "a statement cannot contain both Resource and NotResource")
		case !hasR && !hasNR:
			add(SevError, i, "missing-resource", "identity-based statements must contain Resource or NotResource")
		}
		for _, a := range append(append(Values{}, st.Action...), st.NotAction...) {
			if a != "*" && !actionRe.MatchString(a) {
				add(SevError, i, "bad-action", "action %q is not of the form service:Action", a)
			}
		}
		for _, r := range append(append(Values{}, st.Resource...), st.NotResource...) {
			if r != "*" && !strings.HasPrefix(r, "arn:") {
				add(SevError, i, "bad-resource", "resource %q must be \"*\" or an ARN", r)
			} else if r != "*" && strings.Count(r, ":") < 5 {
				add(SevError, i, "bad-resource", "resource ARN %q has fewer than six parts", r)
			}
		}
		if st.Effect == Allow && hasNA {
			add(SevWarning, i, "allow-notaction", "Allow with NotAction grants every action not listed, including future actions")
		}
		if st.Effect == Allow && hasNR {
			add(SevWarning, i, "allow-notresource", "Allow with NotResource grants every resource not listed")
		}
		if st.Effect == Allow && containsAll(st.Action) && containsAll(st.Resource) && len(st.Condition) == 0 {
			add(SevWarning, i, "full-admin", "statement allows \"*\" on \"*\" (full administrator access)")
		}
		for _, op := range SortedKeys(st.Condition) {
			if knownOperator != nil && !knownOperator(op) {
				add(SevError, i, "bad-condition-operator", "unknown or unsupported condition operator %q", op)
			}
			for _, key := range SortedKeys(st.Condition[op]) {
				if len(st.Condition[op][key]) == 0 {
					add(SevError, i, "empty-condition-values", "condition %s %s has no values", op, key)
				}
			}
		}
	}
	if size, err := d.Size(); err == nil && size > LimitRoleInline {
		add(SevWarning, -1, "too-large", "policy is %d characters; exceeds every IAM policy size quota", size)
	} else if err == nil && size > LimitManaged {
		add(SevWarning, -1, "too-large-managed", "policy is %d characters; exceeds the %d managed-policy quota", size, LimitManaged)
	}
	return out
}

func containsAll(v Values) bool {
	for _, s := range v {
		if s == "*" {
			return true
		}
	}
	return false
}

// HasErrors reports whether any issue is an error.
func HasErrors(issues []Issue) bool {
	for _, i := range issues {
		if i.Severity == SevError {
			return true
		}
	}
	return false
}
