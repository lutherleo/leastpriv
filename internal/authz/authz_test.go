package authz

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lutherleo/leastpriv/internal/engine"
)

const simpleDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

func TestBundle(t *testing.T) {
	inv, err := Parse([]byte(`{"principals":[
		{"arn":"arn:aws:iam::1:role/svc/app","policies":[{"name":"P","document":` + simpleDoc + `},{"name":"P","document":` + simpleDoc + `},{"document":` + simpleDoc + `}],
		 "permissionsBoundary":{"name":"B","document":` + simpleDoc + `}},
		{"arn":"arn:aws:iam::1:user/u","policies":[]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Principals) != 2 {
		t.Fatal("principals")
	}
	p, ok := inv.Find("arn:aws:iam::1:role/app")
	if !ok || p.Kind != "role" || p.Name != "app" || p.Account != "1" {
		t.Fatalf("find by name without path: %+v", p)
	}
	if p.Policies[0].Name != "P" || p.Policies[1].Name != "P#2" || p.Policies[2].Name != "policy3" {
		t.Fatalf("names %v %v %v", p.Policies[0].Name, p.Policies[1].Name, p.Policies[2].Name)
	}
	if i, ok := p.PolicyIndex("P#2"); !ok || i != 1 {
		t.Fatal("PolicyIndex")
	}
	if _, ok := p.PolicyIndex("nope"); ok {
		t.Fatal("PolicyIndex miss")
	}
	set, err := p.PolicySet()
	if err != nil || len(set.Identity) != 3 || set.Boundary == nil {
		t.Fatalf("policy set %v", err)
	}
	if !set.Allows(engine.NewRequest("s3:GetObject", "arn:aws:s3:::b/k")) {
		t.Fatal("evaluation through inventory")
	}
	if _, ok := inv.Find("arn:aws:iam::2:role/app"); ok {
		t.Fatal("different account must not match")
	}
	if _, ok := inv.Find("not-an-arn"); ok {
		t.Fatal("garbage must not match")
	}
}

func TestKey(t *testing.T) {
	cases := map[string]string{
		"arn:aws:iam::1:role/a/b/name": "1/role/name",
		"arn:aws:iam::1:user/u":        "1/user/u",
		"arn:aws:iam::1:root":          "1/root/root",
		"arn:aws:iam::1:group/g":       "",
		"arn:aws:iam::1:policy":        "",
		"x":                            "",
	}
	for in, want := range cases {
		got, ok := Key(in)
		if got != want || ok != (want != "") {
			t.Errorf("Key(%s)=%q,%v", in, got, ok)
		}
	}
}

func TestAuthorizationDetails(t *testing.T) {
	encoded := url.QueryEscape(simpleDoc)
	js := `{
	 "UserDetailList":[{"UserName":"u","Arn":"arn:aws:iam::1:user/u","GroupList":["devs","ghost"],
	   "UserPolicyList":[{"PolicyName":"inline","PolicyDocument":"` + encoded + `"}],
	   "AttachedManagedPolicies":[{"PolicyName":"Missing","PolicyArn":"arn:aws:iam::1:policy/Missing"}],
	   "PermissionsBoundary":{"PermissionsBoundaryArn":"arn:aws:iam::1:policy/Gone"}}],
	 "GroupDetailList":[{"GroupName":"devs","Arn":"arn:aws:iam::1:group/devs","GroupPolicyList":[{"PolicyName":"g","PolicyDocument":` + simpleDoc + `}],
	   "AttachedManagedPolicies":[{"PolicyName":"Shared","PolicyArn":"arn:aws:iam::1:policy/Shared"},{"PolicyName":"Absent","PolicyArn":"arn:aws:iam::1:policy/Absent"}]}],
	 "RoleDetailList":[{"RoleName":"r","Arn":"arn:aws:iam::1:role/r","RolePolicyList":[],
	   "AttachedManagedPolicies":[{"PolicyName":"Shared","PolicyArn":"arn:aws:iam::1:policy/Shared"}],
	   "PermissionsBoundary":{"PermissionsBoundaryArn":"arn:aws:iam::1:policy/Shared"}}],
	 "Policies":[{"PolicyName":"Shared","Arn":"arn:aws:iam::1:policy/Shared","DefaultVersionId":"v2","PolicyVersionList":[
	   {"Document":{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]},"VersionId":"v1","IsDefaultVersion":false},
	   {"Document":` + simpleDoc + `,"VersionId":"v2","IsDefaultVersion":true}]}]
	}`
	inv, err := Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	u, ok := inv.Find("arn:aws:iam::1:user/u")
	if !ok {
		t.Fatal("user missing")
	}
	var names []string
	for _, p := range u.Policies {
		names = append(names, p.Name+"("+p.Source+")")
	}
	if strings.Join(names, ",") != "inline(inline),g(group devs inline),Shared(group devs managed)" {
		t.Fatalf("user policies: %v", names)
	}
	w := strings.Join(u.Warnings, "\n")
	for _, frag := range []string{"policy/Missing", "group ghost", "policy/Absent", "boundary arn:aws:iam::1:policy/Gone"} {
		if !strings.Contains(w, frag) {
			t.Errorf("missing warning about %s in %s", frag, w)
		}
	}
	r, _ := inv.Find("arn:aws:iam::1:role/r")
	if r.Boundary == nil || len(r.Policies) != 1 || r.Policies[0].Doc.Statement[0].Effect != "Allow" {
		t.Fatal("role default version / boundary")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "authz.json")
	if err := os.WriteFile(path, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err != nil {
		t.Fatal(err)
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		`[]`,
		`{"something":1}`,
		`{"principals":[{"arn":"arn:aws:iam::1:group/g","policies":[]}]}`,
		`{"principals":[{"arn":"arn:aws:iam::1:role/a"},{"arn":"arn:aws:iam::1:role/x/a"}]}`,
		`{"principals":[{"arn":"arn:aws:iam::1:role/a","policies":[{"document":{"Version":1}}]}]}`,
		`{"principals":[{"arn":"arn:aws:iam::1:role/a","permissionsBoundary":{"document":"%ZZ%22"}}]}`,
		`{"principals":"x"}`,
		`{"RoleDetailList":[{"Arn":"arn:aws:iam::1:role/a","RolePolicyList":[{"PolicyName":"p","PolicyDocument":"{bad"}]}]}`,
		`{"UserDetailList":[{"Arn":"arn:aws:iam::1:user/a","UserPolicyList":[{"PolicyName":"p","PolicyDocument":1}]}]}`,
		`{"RoleDetailList":[],"GroupDetailList":[{"GroupName":"g","GroupPolicyList":[{"PolicyDocument":[]}]}]}`,
		`{"RoleDetailList":[],"Policies":[{"Arn":"a","DefaultVersionId":"v1","PolicyVersionList":[{"VersionId":"v1","Document":"nope"}]}]}`,
		`{"RoleDetailList":"x"}`,
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("expected error for %s", b)
		}
	}
	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing file")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(p, []byte("{"), 0o600)
	if _, err := LoadFile(p); err == nil {
		t.Fatal("bad file")
	}
}

func TestPolicySetErrors(t *testing.T) {
	inv, err := Parse([]byte(`{"principals":[{"arn":"arn:aws:iam::1:role/a","policies":[{"name":"x","document":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bogus":{"k":"v"}}}]}}],
	"permissionsBoundary":{"name":"b","document":{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Action":"*","Resource":"*"}]}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Principals[0].PolicySet(); err == nil {
		t.Fatal("bad operator must fail compilation")
	}
	inv.Principals[0].Policies = nil
	if _, err := inv.Principals[0].PolicySet(); err == nil {
		t.Fatal("bad boundary must fail compilation")
	}
}
