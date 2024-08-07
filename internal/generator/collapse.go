package generator

import (
	"sort"
	"strings"

	"github.com/lutherleo/leastpriv/internal/arn"
	"github.com/lutherleo/leastpriv/internal/catalog"
)

// Collapse records one wildcard introduced by resource collapsing.
type Collapse struct {
	Action   string `json:"action"`
	Pattern  string `json:"pattern"`
	Replaces int    `json:"replaces"`
	Kind     string `json:"kind"` // "path" or "name-prefix"
}

// collapser implements resource wildcard collapsing.
//
// Resources of one catalog resource type are split into a protected prefix
// (everything before the type's last placeholder, e.g. "arn:aws:s3:::bucket/")
// and a variable suffix. Suffixes sharing a prefix are inserted into a trie
// keyed by '/'-separated path segments. Moderate mode works bottom-up: a node
// is replaced by "path/*" when it has at least minSiblings children and every
// child is a leaf, an unbranched chain ("build-17/manifest.json"), or was
// itself wholly collapsed (a uniform partition such as date folders). Aggressive mode works top-down: the highest node with at
// least minSiblings children of any kind is replaced. Aggressive mode
// also merges leaf names that share a delimiter-terminated prefix
// ("deploy-api", "deploy-worker" -> "deploy-*"). Every candidate pattern must
// pass the covered() check (subsumed by the source statement), otherwise the
// node is left uncollapsed. The root of a flat namespace (queue names,
// function names, role names) is never replaced by a bare "*".
//
// Cost: O(N * L) to build the trie for N resources of path length L, and
// O(N * L) to walk it; name-prefix grouping is O(K^2 * D) per node for K leaf
// children with D delimiters each, which is small in practice.
type collapser struct {
	cat         *catalog.Catalog
	minSiblings int
	bottomUp    bool
	namePrefix  bool
}

type trieNode struct {
	children map[string]*trieNode
	terminal bool
}

func (n *trieNode) child(seg string) *trieNode {
	if n.children == nil {
		n.children = map[string]*trieNode{}
	}
	c, ok := n.children[seg]
	if !ok {
		c = &trieNode{}
		n.children[seg] = c
	}
	return c
}

func (n *trieNode) isLeaf() bool { return len(n.children) == 0 }

// isChain reports whether the subtree is one unbranched path ending in a
// single resource (for example "build-123/manifest.json").
func (n *trieNode) isChain() bool {
	for {
		if n.isLeaf() {
			return n.terminal
		}
		if n.terminal || len(n.children) != 1 {
			return false
		}
		for _, c := range n.children {
			n = c
		}
	}
}

func (n *trieNode) leaves() int {
	c := 0
	if n.terminal {
		c++
	}
	for _, ch := range n.children {
		c += ch.leaves()
	}
	return c
}

func sortedKeys(m map[string]*trieNode) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// collapse returns the (possibly wildcarded) resource patterns covering the
// given resources for one action, plus the collapses performed.
func (c *collapser) collapse(action, service string, resources []string, covered func(string) bool) ([]string, []Collapse) {
	type group struct {
		prefix      string
		rootAllowed bool
		suffixes    []string
	}
	groups := map[string]*group{}
	var out []string
	for _, r := range resources {
		if r == "*" || arn.IsPattern(r) {
			out = append(out, r)
			continue
		}
		rt := c.cat.TypeOf(service, r)
		if rt == nil {
			out = append(out, r)
			continue
		}
		span := rt.VariableSpan(r)
		if span < 0 {
			out = append(out, r)
			continue
		}
		prefix := r[:span]
		g, ok := groups[prefix]
		if !ok {
			g = &group{prefix: prefix, rootAllowed: rt.NamedPlaceholders() >= 2}
			groups[prefix] = g
		}
		g.suffixes = append(g.suffixes, r[span:])
	}
	var events []Collapse
	prefixes := make([]string, 0, len(groups))
	for p := range groups {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)
	for _, p := range prefixes {
		g := groups[p]
		root := &trieNode{}
		for _, s := range g.suffixes {
			n := root
			for _, seg := range strings.Split(s, "/") {
				n = n.child(seg)
			}
			n.terminal = true
		}
		w := walker{c: c, prefix: g.prefix, action: action, covered: covered, rootAllowed: g.rootAllowed}
		pats, _ := w.walk(root, "", true)
		for _, pat := range pats {
			out = append(out, g.prefix+pat)
		}
		events = append(events, w.events...)
	}
	return dedupeSorted(out), events
}

type walker struct {
	c           *collapser
	prefix      string
	action      string
	covered     func(string) bool
	rootAllowed bool
	events      []Collapse
}

// walk returns patterns, relative to the group prefix, that cover the
// subtree rooted at n whose path (with trailing '/', or "" at the root) is
// path. whole reports that the subtree is covered by exactly path+"*".
func (w *walker) walk(n *trieNode, path string, isRoot bool) (pats []string, whole bool) {
	var self []string
	if n.terminal && !isRoot {
		self = append(self, strings.TrimSuffix(path, "/"))
	}
	if n.isLeaf() {
		return self, false
	}
	allowed := !isRoot || w.rootAllowed
	if !w.c.bottomUp && allowed && len(n.children) >= w.c.minSiblings {
		// Aggressive: the highest wide node wins.
		if p, ok := w.collapseNode(n, path, isRoot); ok {
			return append(self, p), !n.terminal || isRoot
		}
	}
	var leafNames []string
	var out []string
	homogeneous := true // every child is a leaf, a single-path chain, or wholly collapsed
	for _, name := range sortedKeys(n.children) {
		ch := n.children[name]
		if ch.isLeaf() {
			if w.c.namePrefix {
				leafNames = append(leafNames, name)
			} else {
				out = append(out, path+name)
			}
			continue
		}
		cp, cw := w.walk(ch, path+name+"/", false)
		homogeneous = homogeneous && (cw || ch.isChain())
		out = append(out, cp...)
	}
	if w.c.bottomUp && allowed && homogeneous && len(n.children) >= w.c.minSiblings {
		// Moderate: collapse only uniform partitions, bottom-up.
		if p, ok := w.collapseNode(n, path, isRoot); ok {
			return append(self, p), !n.terminal || isRoot
		}
	}
	if len(leafNames) > 0 {
		out = append(out, w.namePrefixes(path, leafNames)...)
	}
	return append(self, out...), false
}

// collapseNode replaces the subtree at path with path+"*" when the source
// statement provably covers it, dropping the now-superseded collapse records
// of its descendants.
func (w *walker) collapseNode(n *trieNode, path string, isRoot bool) (string, bool) {
	pat := path + "*"
	if !w.covered(w.prefix + pat) {
		return "", false
	}
	replaced := n.leaves()
	if n.terminal && !isRoot {
		replaced--
	}
	kept := w.events[:0]
	for _, e := range w.events {
		if !strings.HasPrefix(e.Pattern, w.prefix+path) {
			kept = append(kept, e)
		}
	}
	kept = append(kept, Collapse{Action: w.action, Pattern: w.prefix + pat, Replaces: replaced, Kind: "path"})
	w.events = kept
	return pat, true
}

// namePrefixes groups leaf names by their longest shared delimiter-terminated
// prefix, greedily taking the longest prefix with enough members first.
func (w *walker) namePrefixes(path string, names []string) []string {
	remaining := map[string]bool{}
	for _, n := range names {
		remaining[n] = true
	}
	var out []string
	for {
		counts := map[string]int{}
		for n := range remaining {
			for i := 0; i < len(n)-1; i++ {
				switch n[i] {
				case '-', '_', '.':
					if i >= 2 {
						counts[n[:i+1]]++
					}
				}
			}
		}
		best := ""
		for p, cnt := range counts {
			if cnt < w.c.minSiblings {
				continue
			}
			if len(p) > len(best) || (len(p) == len(best) && p < best) {
				best = p
			}
		}
		if best == "" {
			break
		}
		pat := path + best + "*"
		members := 0
		for n := range remaining {
			if strings.HasPrefix(n, best) {
				members++
			}
		}
		if !w.covered(w.prefix + pat) {
			// Exclude this prefix from further consideration by marking its
			// members as settled individually.
			for n := range remaining {
				if strings.HasPrefix(n, best) {
					out = append(out, path+n)
					delete(remaining, n)
				}
			}
			continue
		}
		for n := range remaining {
			if strings.HasPrefix(n, best) {
				delete(remaining, n)
			}
		}
		out = append(out, pat)
		w.events = append(w.events, Collapse{Action: w.action, Pattern: w.prefix + pat, Replaces: members, Kind: "name-prefix"})
	}
	for n := range remaining {
		out = append(out, path+n)
	}
	sort.Strings(out)
	return out
}

func dedupeSorted(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for _, s := range in {
		if len(out) == 0 || s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
