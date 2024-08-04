package engine

import (
	"strings"

	"github.com/lutherleo/leastpriv/internal/glob"
)

// hasVariables reports whether s contains a policy variable reference.
func hasVariables(s string) bool { return strings.Contains(s, "${") }

// variableKeys returns the context keys referenced by policy variables in s.
func variableKeys(s string) []string {
	var keys []string
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			return keys
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			return keys
		}
		key, _, _ := parseVariable(s[i+2 : i+j])
		if key != "" {
			keys = append(keys, strings.ToLower(key))
		}
		s = s[i+j+1:]
	}
}

// parseVariable splits the body of ${...} into the key and an optional
// default value written as ${key, 'default'}. Special bodies *, ? and $
// return an empty key and the literal they stand for.
func parseVariable(body string) (key, def string, hasDef bool) {
	switch body {
	case "*", "?", "$":
		return "", body, true
	}
	if k, rest, ok := strings.Cut(body, ","); ok {
		rest = strings.TrimSpace(rest)
		if len(rest) >= 2 && rest[0] == '\'' && rest[len(rest)-1] == '\'' {
			return strings.TrimSpace(k), rest[1 : len(rest)-1], true
		}
	}
	return strings.TrimSpace(body), "", false
}

// substitute expands policy variables in s for a 2012-10-17 policy. The
// result is a glob pattern in which substituted text is escaped so it never
// acts as a wildcard. It returns No when a referenced key is absent and has
// no default (the element then cannot match), and Maybe when a referenced
// key is unknown; unknown values are replaced by '*' in the returned pattern.
func substitute(s string, req *Request, unk unknownSet) (string, Tri) {
	if !hasVariables(s) {
		return s, Yes
	}
	var b strings.Builder
	state := Yes
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			b.WriteString(s)
			break
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		key, def, hasDef := parseVariable(s[i+2 : i+j])
		switch key {
		case "":
			b.WriteString(glob.Escape(def))
		default:
			vals, st := req.lookup(key)
			switch {
			case st == keyPresent && len(vals) == 1:
				b.WriteString(glob.Escape(vals[0]))
			case st == keyUnknown:
				// Stand in a wildcard so callers can still rule out elements
				// whose fixed text cannot match whatever the value is.
				unk.add(key)
				b.WriteByte('*')
				state = and(state, Maybe)
			case hasDef:
				b.WriteString(glob.Escape(def))
			default:
				// Absent or multivalued keys cannot be substituted.
				return "", No
			}
		}
		s = s[i+j+1:]
	}
	return b.String(), state
}
