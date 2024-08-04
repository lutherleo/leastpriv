package engine

import (
	"fmt"
	"math/big"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/lutherleo/leastpriv/internal/arn"
	"github.com/lutherleo/leastpriv/internal/glob"
)

type family uint8

const (
	famString family = iota
	famStringIgnoreCase
	famStringLike
	famNumeric
	famDate
	famBool
	famIP
	famARN
	famNull
)

type cmp uint8

const (
	cmpEq cmp = iota
	cmpLT
	cmpLE
	cmpGT
	cmpGE
)

type setOp uint8

const (
	setNone setOp = iota
	setForAll
	setForAny
)

type baseOp struct {
	fam     family
	cmp     cmp
	negated bool
}

// baseOperators is the documented Condition operator subset this engine
// evaluates. BinaryEquals is intentionally not supported.
var baseOperators = map[string]baseOp{
	"StringEquals":              {fam: famString},
	"StringNotEquals":           {fam: famString, negated: true},
	"StringEqualsIgnoreCase":    {fam: famStringIgnoreCase},
	"StringNotEqualsIgnoreCase": {fam: famStringIgnoreCase, negated: true},
	"StringLike":                {fam: famStringLike},
	"StringNotLike":             {fam: famStringLike, negated: true},
	"NumericEquals":             {fam: famNumeric, cmp: cmpEq},
	"NumericNotEquals":          {fam: famNumeric, cmp: cmpEq, negated: true},
	"NumericLessThan":           {fam: famNumeric, cmp: cmpLT},
	"NumericLessThanEquals":     {fam: famNumeric, cmp: cmpLE},
	"NumericGreaterThan":        {fam: famNumeric, cmp: cmpGT},
	"NumericGreaterThanEquals":  {fam: famNumeric, cmp: cmpGE},
	"DateEquals":                {fam: famDate, cmp: cmpEq},
	"DateNotEquals":             {fam: famDate, cmp: cmpEq, negated: true},
	"DateLessThan":              {fam: famDate, cmp: cmpLT},
	"DateLessThanEquals":        {fam: famDate, cmp: cmpLE},
	"DateGreaterThan":           {fam: famDate, cmp: cmpGT},
	"DateGreaterThanEquals":     {fam: famDate, cmp: cmpGE},
	"Bool":                      {fam: famBool},
	"IpAddress":                 {fam: famIP},
	"NotIpAddress":              {fam: famIP, negated: true},
	"ArnEquals":                 {fam: famARN},
	"ArnLike":                   {fam: famARN},
	"ArnNotEquals":              {fam: famARN, negated: true},
	"ArnNotLike":                {fam: famARN, negated: true},
	"Null":                      {fam: famNull},
}

// condition is one (operator, key, values) triple of a Condition block.
type condition struct {
	op       string
	base     baseOp
	set      setOp
	ifExists bool
	key      string
	values   []string
	hasVars  bool
}

// parseOperator decodes "[ForAllValues:|ForAnyValue:]Base[IfExists]".
func parseOperator(op string) (baseOp, setOp, bool, error) {
	name := op
	set := setNone
	switch {
	case strings.HasPrefix(name, "ForAllValues:"):
		set, name = setForAll, strings.TrimPrefix(name, "ForAllValues:")
	case strings.HasPrefix(name, "ForAnyValue:"):
		set, name = setForAny, strings.TrimPrefix(name, "ForAnyValue:")
	}
	ifExists := false
	if strings.HasSuffix(name, "IfExists") {
		ifExists, name = true, strings.TrimSuffix(name, "IfExists")
	}
	b, ok := baseOperators[name]
	if !ok {
		return baseOp{}, 0, false, fmt.Errorf("unsupported condition operator %q", op)
	}
	if b.fam == famNull && (ifExists || set != setNone) {
		return baseOp{}, 0, false, fmt.Errorf("operator %q: Null cannot be combined with IfExists or set operators", op)
	}
	return b, set, ifExists, nil
}

// KnownOperator reports whether op is a condition operator the engine supports.
func KnownOperator(op string) bool {
	_, _, _, err := parseOperator(op)
	return err == nil
}

func newCondition(op, key string, values []string, version string) (condition, error) {
	b, set, ifExists, err := parseOperator(op)
	if err != nil {
		return condition{}, err
	}
	c := condition{op: op, base: b, set: set, ifExists: ifExists, key: strings.ToLower(key), values: values}
	for _, v := range values {
		if version != "2008-10-17" && hasVariables(v) {
			c.hasVars = true
			continue
		}
		if err := checkLiteral(b.fam, v); err != nil {
			return condition{}, fmt.Errorf("operator %s key %s: %w", op, key, err)
		}
	}
	return c, nil
}

// checkLiteral rejects policy values that can never be compared.
func checkLiteral(f family, v string) error {
	switch f {
	case famNumeric:
		if _, ok := parseNumber(v); !ok {
			return fmt.Errorf("value %q is not numeric", v)
		}
	case famDate:
		if _, ok := parseDate(v); !ok {
			return fmt.Errorf("value %q is not a date", v)
		}
	case famBool, famNull:
		if _, err := strconv.ParseBool(strings.ToLower(v)); err != nil {
			return fmt.Errorf("value %q is not a boolean", v)
		}
	case famIP:
		if _, ok := parseCIDR(v); !ok {
			return fmt.Errorf("value %q is not an IP address or CIDR", v)
		}
	}
	return nil
}

// eval evaluates the condition with IAM semantics:
//   - values for one key are ORed; negated operators negate that OR;
//   - an absent key fails positive operators and satisfies negated ones,
//     IfExists operators and ForAllValues; it fails ForAnyValue;
//   - Null:true holds exactly when the key is absent;
//   - for a multivalued key without a set operator, a positive operator
//     holds when any request value matches.
func (c *condition) eval(req *Request, unk unknownSet) Tri {
	vals, st := req.lookup(c.key)
	if st == keyUnknown {
		unk.add(c.key)
		return Maybe
	}
	if c.base.fam == famNull {
		// Null:"true" holds when the key is absent, Null:"false" when present.
		matched := false
		for _, v := range c.values {
			if b, err := strconv.ParseBool(strings.ToLower(v)); err == nil && b == (st == keyAbsent) {
				matched = true
			}
		}
		return triOf(matched)
	}
	if st == keyAbsent {
		switch {
		case c.ifExists, c.set == setForAll:
			return Yes
		case c.set == setForAny:
			return No
		case c.base.negated:
			return Yes
		default:
			return No
		}
	}
	policyVals, pstate := c.expand(req, unk)
	if pstate == No {
		policyVals = nil
	}
	// matchOne reports whether a single request value satisfies the
	// operator (including negation) against the policy values.
	matchOne := func(v string) Tri {
		pos := No
		for _, pv := range policyVals {
			if compare(c.base, pv, v) {
				pos = Yes
				break
			}
		}
		if pos == No && pstate == Maybe {
			pos = Maybe
		}
		if c.base.negated {
			return not(pos)
		}
		return pos
	}
	switch c.set {
	case setForAll:
		res := Yes
		for _, v := range vals {
			res = and(res, matchOne(v))
		}
		return res
	case setForAny:
		res := No
		for _, v := range vals {
			res = or(res, matchOne(v))
		}
		return res
	default:
		if c.base.negated {
			// The negated operator holds when no request value matches the
			// positive form.
			res := Yes
			for _, v := range vals {
				res = and(res, matchOne(v))
			}
			return res
		}
		res := No
		for _, v := range vals {
			res = or(res, matchOne(v))
		}
		return res
	}
}

// expand substitutes policy variables in the condition values. Values whose
// variables are absent are dropped; unknown variables yield Maybe.
func (c *condition) expand(req *Request, unk unknownSet) ([]string, Tri) {
	if !c.hasVars {
		return c.values, Yes
	}
	out := make([]string, 0, len(c.values))
	state := Yes
	for _, v := range c.values {
		s, t := substitute(v, req, unk)
		switch t {
		case Yes:
			out = append(out, s)
		case Maybe:
			state = Maybe
		}
	}
	if len(out) == 0 && state == Yes {
		return nil, No
	}
	return out, state
}

// compare applies the positive form of the operator to one policy value and
// one request value.
func compare(b baseOp, policyVal, reqVal string) bool {
	switch b.fam {
	case famString:
		return glob.Unescape(policyVal) == reqVal
	case famStringIgnoreCase:
		return strings.EqualFold(glob.Unescape(policyVal), reqVal)
	case famStringLike:
		return glob.Match(policyVal, reqVal)
	case famARN:
		return arn.Match(policyVal, reqVal)
	case famBool:
		p, err1 := strconv.ParseBool(strings.ToLower(policyVal))
		r, err2 := strconv.ParseBool(strings.ToLower(reqVal))
		return err1 == nil && err2 == nil && p == r
	case famIP:
		pfx, ok1 := parseCIDR(policyVal)
		ip, err := netip.ParseAddr(reqVal)
		return ok1 && err == nil && pfx.Contains(ip.Unmap())
	case famNumeric:
		p, ok1 := parseNumber(policyVal)
		r, ok2 := parseNumber(reqVal)
		return ok1 && ok2 && ordered(b.cmp, r.Cmp(p))
	case famDate:
		p, ok1 := parseDate(policyVal)
		r, ok2 := parseDate(reqVal)
		return ok1 && ok2 && ordered(b.cmp, r.Compare(p))
	}
	return false
}

// ordered interprets c = compare(request, policy) for the operator.
func ordered(op cmp, c int) bool {
	switch op {
	case cmpLT:
		return c < 0
	case cmpLE:
		return c <= 0
	case cmpGT:
		return c > 0
	case cmpGE:
		return c >= 0
	default:
		return c == 0
	}
}

func parseNumber(s string) (*big.Rat, bool) {
	r, ok := new(big.Rat).SetString(strings.TrimSpace(s))
	return r, ok
}

var dateLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05Z0700",
	"2006-01-02T15:04Z07:00",
	"2006-01-02T15:04Z",
	"2006-01-02",
}

// parseDate accepts ISO 8601 forms and epoch seconds, as IAM does.
func parseDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), true
	}
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func parseCIDR(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}
