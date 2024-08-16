package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseForms(t *testing.T) {
	d, err := Parse([]byte(`{"Version":"2012-10-17","Id":"x","Statement":{"Sid":"One","Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::b/*"],
		"Condition":{"Bool":{"aws:SecureTransport":true},"NumericLessThan":{"s3:max-keys":10},"StringEquals":{"k":["a","b"]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Statement) != 1 || d.ID != "x" {
		t.Fatalf("%+v", d)
	}
	st := d.Statement[0]
	if st.Action[0] != "s3:GetObject" || st.Resource[0] != "arn:aws:s3:::b/*" {
		t.Fatalf("%+v", st)
	}
	if st.Condition["Bool"]["aws:SecureTransport"][0] != "true" || st.Condition["NumericLessThan"]["s3:max-keys"][0] != "10" {
		t.Fatalf("condition scalars not normalised: %+v", st.Condition)
	}
	if !st.Has("Action") || st.Has("NotAction") || !st.Has("Condition") {
		t.Fatal("Has")
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		`[]`,
		`{"version":"2012-10-17","Statement":[]}`,
		`{"Version":"2012-10-17","Statement":[{"effect":"Allow"}]}`,
		`{"Version":"2012-10-17","Statement":[1]}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":{"a":1}}}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":[null]}]}`,
		`{"Version":"2012-10-17","Statement":"x"}`,
		`{"Version":1}`,
		`{"Id":1}`,
		`{"Version":"2012-10-17","Statement":[{"Sid":1}]}`,
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("expected error for %s", b)
		}
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	src := `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Deny","NotAction":["iam:*","sts:*"],"NotResource":"arn:aws:iam::1:role/x","Condition":{"StringLike":{"aws:userid":"AROA*"}}},{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	d, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != src {
		t.Fatalf("canonical form changed:\n%s\n%s", b, src)
	}
	pretty, err := d.Pretty()
	if err != nil || !strings.HasSuffix(string(pretty), "}\n") || !strings.Contains(string(pretty), "\n  \"Statement\"") {
		t.Fatalf("pretty: %s %v", pretty, err)
	}
	n, err := d.Size()
	if err != nil || n != len(src) {
		t.Fatalf("size %d want %d", n, len(src))
	}
	empty, _ := json.Marshal(Document{Version: Version2012})
	if string(empty) != `{"Version":"2012-10-17","Statement":[]}` {
		t.Fatal(string(empty))
	}
}

func TestCloneAndKeys(t *testing.T) {
	d, _ := Parse([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"Bool":{"k":"true"}}}]}`))
	c := d.Statement[0].Clone()
	c.Action[0] = "changed"
	c.Condition["Bool"]["k"][0] = "false"
	if d.Statement[0].Action[0] != "s3:*" || d.Statement[0].Condition["Bool"]["k"][0] != "true" {
		t.Fatal("clone is shallow")
	}
	if !c.Has("Principal") || c.Has("NotResource") {
		t.Fatal("Has on clone")
	}
	if d.Statement[0].Condition.Key() != `{"Bool":{"k":"true"}}` || Condition(nil).Key() != "" || Condition(nil).Clone() != nil {
		t.Fatal("condition key")
	}
	if ServiceOf("S3:GetObject") != "s3" || ServiceOf("*") != "" {
		t.Fatal("ServiceOf")
	}
	if (&Document{}).EffectiveVersion() != Version2008 {
		t.Fatal("default version")
	}
	if got := SortedKeys(map[string]int{"b": 1, "a": 2}); got[0] != "a" {
		t.Fatal("sorted keys")
	}
}

func codes(issues []Issue) map[string]bool {
	m := map[string]bool{}
	for _, i := range issues {
		m[i.Code] = true
	}
	return m
}

func TestValidate(t *testing.T) {
	cases := []struct {
		doc  string
		want []string
		err  bool
	}{
		{`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`, nil, false},
		{`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, []string{"missing-version"}, false},
		{`{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, []string{"old-version"}, false},
		{`{"Version":"2020-01-01","Statement":[]}`, []string{"bad-version", "no-statements"}, true},
		{`{"Version":"2012-10-17","Statement":[{"Sid":"a-b","Effect":"allow","Action":"s3:GetObject","Resource":"*"}]}`, []string{"bad-sid", "bad-effect"}, true},
		{`{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:x","Resource":"*"},{"Sid":"A","Effect":"Allow","Action":"s3:y","Resource":"*"}]}`, []string{"duplicate-sid"}, true},
		{`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:x","Resource":"*"}]}`, []string{"principal-in-identity-policy"}, true},
		{`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:x","NotAction":"s3:y","Resource":"*","NotResource":"*"}]}`, []string{"action-and-notaction", "resource-and-notresource"}, true},
		{`{"Version":"2012-10-17","Statement":[{"Effect":"Allow"}]}`, []string{"missing-action", "missing-resource"}, true},
		{`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"GetObject","Resource":"bucket"}]}`, []string{"bad-action", "bad-resource"}, true},
		{`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:x","Resource":"arn:aws:s3"}]}`, []string{"bad-resource"}, true},
		{`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"iam:*","NotResource":"arn:aws:s3:::b"}]}`, []string{"allow-notaction", "allow-notresource"}, false},
		{`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, []string{"full-admin"}, false},
		{`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Weird":{"k":[]}}}]}`, []string{"bad-condition-operator", "empty-condition-values"}, true},
	}
	known := func(op string) bool { return op != "Weird" }
	for _, c := range cases {
		d, err := Parse([]byte(c.doc))
		if err != nil {
			t.Fatalf("%s: %v", c.doc, err)
		}
		issues := Validate(d, known)
		got := codes(issues)
		for _, w := range c.want {
			if !got[w] {
				t.Errorf("%s: missing %s in %v", c.doc, w, issues)
			}
		}
		if c.want == nil && len(issues) != 0 {
			t.Errorf("%s: unexpected issues %v", c.doc, issues)
		}
		if HasErrors(issues) != c.err {
			t.Errorf("%s: HasErrors=%v", c.doc, HasErrors(issues))
		}
	}
	// Operator checking is optional.
	d, _ := Parse([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Weird":{"k":"v"}}}]}`))
	if codes(Validate(d, nil))["bad-condition-operator"] {
		t.Fatal("nil predicate must skip operator check")
	}
	if !strings.Contains(Issue{Severity: SevError, Statement: 2, Code: "c", Message: "m"}.String(), "statement 2") ||
		!strings.Contains(Issue{Statement: -1}.String(), "document") {
		t.Fatal("issue string")
	}
}

func TestValidateSize(t *testing.T) {
	var sts []string
	for i := 0; i < 120; i++ {
		sts = append(sts, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-with-a-long-name/some/long/prefix/`+strings.Repeat("x", 20)+`"}`)
	}
	d, err := Parse([]byte(`{"Version":"2012-10-17","Statement":[` + strings.Join(sts, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !codes(Validate(d, nil))["too-large"] {
		t.Fatal("expected too-large")
	}
	d.Statement = d.Statement[:60]
	if !codes(Validate(d, nil))["too-large-managed"] {
		t.Fatal("expected too-large-managed")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	f.Add(`{"Statement":[{"Condition":{"Bool":{"k":[true,1,"x"]}}}]}`)
	f.Fuzz(func(t *testing.T, s string) {
		d, err := Parse([]byte(s))
		if err != nil {
			return
		}
		_ = Validate(d, nil)
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatalf("marshal after successful parse: %v", err)
		}
		if _, err := Parse(b); err != nil {
			t.Fatalf("re-parse of canonical form failed: %v\n%s", err, b)
		}
	})
}
