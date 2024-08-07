package generator

import (
	"fmt"

	"github.com/lutherleo/leastpriv/internal/policy"
)

// Split packs a policy's statements into several documents, each at most
// limit characters (whitespace excluded), using first-fit in statement
// order. Attaching all parts to the principal is equivalent to attaching the
// original, because identity policies combine by union and a Deny in any
// attached policy applies to every request. Cost: O(S * P) size checks for S
// statements and P parts.
func Split(doc *policy.Document, limit int) ([]*policy.Document, error) {
	var parts []*policy.Document
	for _, st := range doc.Statement {
		placed := false
		for _, p := range parts {
			p.Statement = append(p.Statement, st)
			if size, err := p.Size(); err == nil && size <= limit {
				placed = true
				break
			}
			p.Statement = p.Statement[:len(p.Statement)-1]
		}
		if placed {
			continue
		}
		p := &policy.Document{Version: doc.Version, Statement: []policy.Statement{st}}
		size, err := p.Size()
		if err != nil {
			return nil, err
		}
		if size > limit {
			return nil, fmt.Errorf("statement %q alone is %d characters, above the %d limit; use a more aggressive level", st.Sid, size, limit)
		}
		parts = append(parts, p)
	}
	return parts, nil
}
