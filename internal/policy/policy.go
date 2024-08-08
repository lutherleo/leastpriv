// Package policy models IAM identity-based policy documents: strict JSON
// decoding (exact element names, string-or-array values), validation against
// the IAM grammar, and canonical JSON encoding.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Policy language versions.
const (
	Version2012 = "2012-10-17"
	Version2008 = "2008-10-17"
)

// Effect is the Effect element of a statement.
type Effect string

// Statement effects.
const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// Values is a policy value list. In JSON it may be a single string or an
// array of strings; Condition values may also be booleans or numbers, which
// are normalised to their string form.
type Values []string

// UnmarshalJSON accepts a string, number, boolean or an array of those.
func (v *Values) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '[' {
		var raw []json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		out := make(Values, 0, len(raw))
		for _, r := range raw {
			s, err := scalar(r)
			if err != nil {
				return err
			}
			out = append(out, s)
		}
		*v = out
		return nil
	}
	s, err := scalar(data)
	if err != nil {
		return err
	}
	*v = Values{s}
	return nil
}

// MarshalJSON writes a single value as a string and several as an array.
func (v Values) MarshalJSON() ([]byte, error) {
	if len(v) == 1 {
		return json.Marshal(v[0])
	}
	return json.Marshal([]string(v))
}

func scalar(data []byte) (string, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return "", fmt.Errorf("empty value")
	}
	switch data[0] {
	case '"':
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return "", err
		}
		return s, nil
	case 'n':
		return "", fmt.Errorf("null is not a valid policy value")
	case 't', 'f':
		var b bool
		if err := json.Unmarshal(data, &b); err != nil {
			return "", err
		}
		return strconv.FormatBool(b), nil
	default:
		var n json.Number
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(&n); err != nil {
			return "", fmt.Errorf("unsupported value %s", string(data))
		}
		return n.String(), nil
	}
}

// Condition is the Condition element: operator -> condition key -> values.
type Condition map[string]map[string]Values

// Statement is one statement of a policy document.
type Statement struct {
	Sid         string
	Effect      Effect
	Principal   json.RawMessage
	Action      Values
	NotAction   Values
	Resource    Values
	NotResource Values
	Condition   Condition
	// present records which optional elements appeared in the source JSON,
	// so validation can tell an empty list from a missing element.
	present map[string]bool
}

// Has reports whether the named element was present when the statement was
// decoded (or set by a constructor).
func (s *Statement) Has(element string) bool {
	if s.present != nil {
		return s.present[element]
	}
	switch element {
	case "Action":
		return s.Action != nil
	case "NotAction":
		return s.NotAction != nil
	case "Resource":
		return s.Resource != nil
	case "NotResource":
		return s.NotResource != nil
	case "Principal":
		return len(s.Principal) > 0
	}
	return false
}

// Clone returns a deep copy of the statement.
func (s *Statement) Clone() Statement {
	c := Statement{
		Sid:         s.Sid,
		Effect:      s.Effect,
		Action:      cloneValues(s.Action),
		NotAction:   cloneValues(s.NotAction),
		Resource:    cloneValues(s.Resource),
		NotResource: cloneValues(s.NotResource),
		Condition:   s.Condition.Clone(),
	}
	if s.Principal != nil {
		c.Principal = append(json.RawMessage(nil), s.Principal...)
	}
	return c
}

func cloneValues(v Values) Values {
	if v == nil {
		return nil
	}
	return append(Values(nil), v...)
}

// Clone returns a deep copy of the condition block.
func (c Condition) Clone() Condition {
	if c == nil {
		return nil
	}
	out := make(Condition, len(c))
	for op, kv := range c {
		m := make(map[string]Values, len(kv))
		for k, v := range kv {
			m[k] = cloneValues(v)
		}
		out[op] = m
	}
	return out
}

// Key returns a canonical string for the condition block, used to group
// statements that share identical conditions.
func (c Condition) Key() string {
	if len(c) == 0 {
		return ""
	}
	b, err := json.Marshal(c) // map keys are sorted by encoding/json
	if err != nil {
		return fmt.Sprintf("%v", map[string]map[string]Values(c))
	}
	return string(b)
}

var statementKeys = map[string]bool{
	"Sid": true, "Effect": true, "Principal": true, "NotPrincipal": true,
	"Action": true, "NotAction": true, "Resource": true, "NotResource": true, "Condition": true,
}

// UnmarshalJSON decodes a statement with exact (case-sensitive) element names.
func (s *Statement) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("statement must be a JSON object: %w", err)
	}
	*s = Statement{present: map[string]bool{}}
	for k, v := range raw {
		if !statementKeys[k] {
			return fmt.Errorf("unknown statement element %q (element names are case-sensitive)", k)
		}
		s.present[k] = true
		var err error
		switch k {
		case "Sid":
			err = json.Unmarshal(v, &s.Sid)
		case "Effect":
			var e string
			err = json.Unmarshal(v, &e)
			s.Effect = Effect(e)
		case "Principal", "NotPrincipal":
			s.Principal = append(json.RawMessage(nil), v...)
		case "Action":
			err = json.Unmarshal(v, &s.Action)
		case "NotAction":
			err = json.Unmarshal(v, &s.NotAction)
		case "Resource":
			err = json.Unmarshal(v, &s.Resource)
		case "NotResource":
			err = json.Unmarshal(v, &s.NotResource)
		case "Condition":
			err = json.Unmarshal(v, &s.Condition)
		}
		if err != nil {
			return fmt.Errorf("element %s: %w", k, err)
		}
	}
	return nil
}

// MarshalJSON writes the statement with elements in conventional order.
func (s Statement) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	first := true
	field := func(name string, v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		buf.WriteString(strconv.Quote(name))
		buf.WriteByte(':')
		buf.Write(b)
		return nil
	}
	type kv struct {
		name string
		val  any
		ok   bool
	}
	fields := []kv{
		{"Sid", s.Sid, s.Sid != ""},
		{"Effect", string(s.Effect), true},
		{"Principal", s.Principal, len(s.Principal) > 0},
		{"Action", s.Action, s.Action != nil},
		{"NotAction", s.NotAction, s.NotAction != nil},
		{"Resource", s.Resource, s.Resource != nil},
		{"NotResource", s.NotResource, s.NotResource != nil},
		{"Condition", s.Condition, len(s.Condition) > 0},
	}
	for _, f := range fields {
		if !f.ok {
			continue
		}
		if err := field(f.name, f.val); err != nil {
			return nil, err
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// Document is an IAM policy document.
type Document struct {
	Version   string
	ID        string
	Statement []Statement
}

// UnmarshalJSON decodes a policy document; Statement may be an object or array.
func (d *Document) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("policy document must be a JSON object: %w", err)
	}
	*d = Document{}
	for k, v := range raw {
		switch k {
		case "Version":
			if err := json.Unmarshal(v, &d.Version); err != nil {
				return fmt.Errorf("element Version: %w", err)
			}
		case "Id":
			if err := json.Unmarshal(v, &d.ID); err != nil {
				return fmt.Errorf("element Id: %w", err)
			}
		case "Statement":
			v = bytes.TrimSpace(v)
			if len(v) > 0 && v[0] == '{' {
				var st Statement
				if err := json.Unmarshal(v, &st); err != nil {
					return fmt.Errorf("statement 0: %w", err)
				}
				d.Statement = []Statement{st}
				continue
			}
			var raws []json.RawMessage
			if err := json.Unmarshal(v, &raws); err != nil {
				return fmt.Errorf("element Statement: %w", err)
			}
			d.Statement = make([]Statement, len(raws))
			for i, r := range raws {
				if err := json.Unmarshal(r, &d.Statement[i]); err != nil {
					return fmt.Errorf("statement %d: %w", i, err)
				}
			}
		default:
			return fmt.Errorf("unknown policy element %q (element names are case-sensitive)", k)
		}
	}
	return nil
}

// MarshalJSON writes Version, Id and Statement (always as an array).
func (d Document) MarshalJSON() ([]byte, error) {
	type out struct {
		Version   string      `json:"Version,omitempty"`
		ID        string      `json:"Id,omitempty"`
		Statement []Statement `json:"Statement"`
	}
	st := d.Statement
	if st == nil {
		st = []Statement{}
	}
	return json.Marshal(out{Version: d.Version, ID: d.ID, Statement: st})
}

// Parse decodes a policy document from JSON.
func Parse(data []byte) (*Document, error) {
	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Pretty returns the canonical indented JSON encoding of the document.
func (d *Document) Pretty() ([]byte, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// Size returns the policy size the way IAM quotas count it: the length of
// the document with insignificant whitespace removed.
func (d *Document) Size() (int, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// EffectiveVersion returns the version used for policy-variable semantics.
// A document without Version is treated as 2008-10-17, as IAM does.
func (d *Document) EffectiveVersion() string {
	if d.Version == "" {
		return Version2008
	}
	return d.Version
}

// SortedKeys returns the keys of a condition key map in sorted order.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ServiceOf returns the lower-cased service prefix of an action such as
// "s3:GetObject", or "" for "*" and malformed actions.
func ServiceOf(action string) string {
	i := strings.IndexByte(action, ':')
	if i <= 0 {
		return ""
	}
	return strings.ToLower(action[:i])
}
