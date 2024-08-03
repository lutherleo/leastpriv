// Package authz loads the IAM principals to analyse and the policies
// attached to them.
//
// Two input formats are accepted and auto-detected:
//
//   - the output of `aws iam get-account-authorization-details`
//     (UserDetailList / GroupDetailList / RoleDetailList / Policies), with
//     policy documents either as JSON objects or URL-encoded strings;
//   - a small bundle format: {"principals":[{"arn": "...", "policies":
//     [{"name": "...", "document": {...}}], "permissionsBoundary": {...}}]}.
//
// Users inherit the inline and managed policies of their groups.
package authz

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/lutherleo/leastpriv/internal/arn"
	"github.com/lutherleo/leastpriv/internal/engine"
	"github.com/lutherleo/leastpriv/internal/policy"
)

// NamedDoc is a policy document with its provenance.
type NamedDoc struct {
	Name   string           `json:"name"`
	Source string           `json:"source"`
	Doc    *policy.Document `json:"document"`
}

// Principal is an IAM user or role with its identity policies.
type Principal struct {
	ARN      string     `json:"arn"`
	Kind     string     `json:"kind"` // "user", "role" or "root"
	Name     string     `json:"name"`
	Account  string     `json:"account"`
	Policies []NamedDoc `json:"policies"`
	Boundary *NamedDoc  `json:"permissionsBoundary,omitempty"`
	Warnings []string   `json:"warnings,omitempty"`
}

// Inventory is the set of principals loaded from one input.
type Inventory struct {
	Principals []*Principal
	byKey      map[string]*Principal
}

// Key returns the identity used to match principals across inputs:
// account, kind and name. Role paths are ignored because CloudTrail session
// ARNs omit them, and role names are unique within an account.
func Key(principalARN string) (string, bool) {
	a, err := arn.Parse(principalARN)
	if err != nil {
		return "", false
	}
	kind, rest, ok := strings.Cut(a.Resource, "/")
	if a.Resource == "root" {
		return a.Account + "/root/root", true
	}
	if !ok || (kind != "user" && kind != "role") {
		return "", false
	}
	name := rest
	if i := strings.LastIndexByte(rest, '/'); i >= 0 {
		name = rest[i+1:]
	}
	return a.Account + "/" + kind + "/" + name, true
}

// Find returns the principal matching an ARN (user, role, or assumed-role
// derived role ARN).
func (inv *Inventory) Find(principalARN string) (*Principal, bool) {
	k, ok := Key(principalARN)
	if !ok {
		return nil, false
	}
	p, ok := inv.byKey[k]
	return p, ok
}

// PolicySet compiles the principal's policies for evaluation.
func (p *Principal) PolicySet() (*engine.Set, error) {
	s := &engine.Set{}
	for _, nd := range p.Policies {
		c, err := engine.Compile(nd.Name, nd.Doc)
		if err != nil {
			return nil, fmt.Errorf("principal %s: %w", p.ARN, err)
		}
		s.Identity = append(s.Identity, c)
	}
	if p.Boundary != nil {
		c, err := engine.Compile(p.Boundary.Name, p.Boundary.Doc)
		if err != nil {
			return nil, fmt.Errorf("principal %s boundary: %w", p.ARN, err)
		}
		s.Boundary = c
	}
	return s, nil
}

// LoadFile reads an inventory from a file.
func LoadFile(path string) (*Inventory, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- explicit user input
	if err != nil {
		return nil, err
	}
	inv, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return inv, nil
}

// Parse detects the input format and loads the inventory.
func Parse(data []byte) (*Inventory, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("decode inventory: %w", err)
	}
	var inv *Inventory
	var err error
	switch {
	case probe["principals"] != nil:
		inv, err = parseBundle(data)
	case probe["RoleDetailList"] != nil || probe["UserDetailList"] != nil:
		inv, err = parseAuthDetails(data)
	default:
		return nil, fmt.Errorf("unrecognised inventory: expected get-account-authorization-details output or a {\"principals\": [...]} bundle")
	}
	if err != nil {
		return nil, err
	}
	inv.byKey = map[string]*Principal{}
	sort.Slice(inv.Principals, func(i, j int) bool { return inv.Principals[i].ARN < inv.Principals[j].ARN })
	for _, p := range inv.Principals {
		k, ok := Key(p.ARN)
		if !ok {
			return nil, fmt.Errorf("principal ARN %q is not an IAM user or role ARN", p.ARN)
		}
		if _, dup := inv.byKey[k]; dup {
			return nil, fmt.Errorf("duplicate principal %s", p.ARN)
		}
		inv.byKey[k] = p
		uniqueNames(p.Policies)
		a, _ := arn.Parse(p.ARN)
		p.Account = a.Account
		kind, rest, _ := strings.Cut(a.Resource, "/")
		if a.Resource == "root" {
			kind, rest = "root", "root"
		}
		p.Kind = kind
		if i := strings.LastIndexByte(rest, '/'); i >= 0 {
			rest = rest[i+1:]
		}
		p.Name = rest
	}
	return inv, nil
}

// uniqueNames suffixes repeated policy names ("name#2") so statement
// references can be traced back to exactly one attached policy.
func uniqueNames(docs []NamedDoc) {
	seen := map[string]int{}
	for i := range docs {
		seen[docs[i].Name]++
		if n := seen[docs[i].Name]; n > 1 {
			docs[i].Name = fmt.Sprintf("%s#%d", docs[i].Name, n)
		}
	}
}

// PolicyIndex returns the index of the attached policy with the given name.
func (p *Principal) PolicyIndex(name string) (int, bool) {
	for i := range p.Policies {
		if p.Policies[i].Name == name {
			return i, true
		}
	}
	return -1, false
}

// decodeDocument accepts a policy document as a JSON object or as a
// URL-encoded JSON string (the raw IAM API form).
func decodeDocument(raw json.RawMessage) (*policy.Document, error) {
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		if strings.HasPrefix(strings.TrimSpace(s), "%7B") || strings.Contains(s, "%22") {
			dec, err := url.QueryUnescape(s)
			if err != nil {
				return nil, fmt.Errorf("url-decode policy document: %w", err)
			}
			s = dec
		}
		return policy.Parse([]byte(s))
	}
	return policy.Parse(raw)
}

type bundle struct {
	Principals []struct {
		ARN      string `json:"arn"`
		Policies []struct {
			Name     string          `json:"name"`
			Document json.RawMessage `json:"document"`
		} `json:"policies"`
		PermissionsBoundary *struct {
			Name     string          `json:"name"`
			Document json.RawMessage `json:"document"`
		} `json:"permissionsBoundary"`
	} `json:"principals"`
}

func parseBundle(data []byte) (*Inventory, error) {
	var b bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("decode bundle: %w", err)
	}
	inv := &Inventory{}
	for _, bp := range b.Principals {
		p := &Principal{ARN: bp.ARN}
		for i, pol := range bp.Policies {
			doc, err := decodeDocument(pol.Document)
			if err != nil {
				return nil, fmt.Errorf("principal %s policy %d: %w", bp.ARN, i, err)
			}
			name := pol.Name
			if name == "" {
				name = fmt.Sprintf("policy%d", i+1)
			}
			p.Policies = append(p.Policies, NamedDoc{Name: name, Source: "bundle", Doc: doc})
		}
		if bp.PermissionsBoundary != nil {
			doc, err := decodeDocument(bp.PermissionsBoundary.Document)
			if err != nil {
				return nil, fmt.Errorf("principal %s boundary: %w", bp.ARN, err)
			}
			p.Boundary = &NamedDoc{Name: bp.PermissionsBoundary.Name, Source: "boundary", Doc: doc}
		}
		inv.Principals = append(inv.Principals, p)
	}
	return inv, nil
}

type inlinePolicy struct {
	PolicyName     string          `json:"PolicyName"`
	PolicyDocument json.RawMessage `json:"PolicyDocument"`
}

type attached struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

type boundaryRef struct {
	PermissionsBoundaryArn string `json:"PermissionsBoundaryArn"`
}

type authDetails struct {
	UserDetailList []struct {
		UserName                string         `json:"UserName"`
		Arn                     string         `json:"Arn"`
		GroupList               []string       `json:"GroupList"`
		UserPolicyList          []inlinePolicy `json:"UserPolicyList"`
		AttachedManagedPolicies []attached     `json:"AttachedManagedPolicies"`
		PermissionsBoundary     *boundaryRef   `json:"PermissionsBoundary"`
	} `json:"UserDetailList"`
	GroupDetailList []struct {
		GroupName               string         `json:"GroupName"`
		Arn                     string         `json:"Arn"`
		GroupPolicyList         []inlinePolicy `json:"GroupPolicyList"`
		AttachedManagedPolicies []attached     `json:"AttachedManagedPolicies"`
	} `json:"GroupDetailList"`
	RoleDetailList []struct {
		RoleName                string         `json:"RoleName"`
		Arn                     string         `json:"Arn"`
		RolePolicyList          []inlinePolicy `json:"RolePolicyList"`
		AttachedManagedPolicies []attached     `json:"AttachedManagedPolicies"`
		PermissionsBoundary     *boundaryRef   `json:"PermissionsBoundary"`
	} `json:"RoleDetailList"`
	Policies []struct {
		PolicyName        string `json:"PolicyName"`
		Arn               string `json:"Arn"`
		DefaultVersionID  string `json:"DefaultVersionId"`
		PolicyVersionList []struct {
			Document         json.RawMessage `json:"Document"`
			VersionID        string          `json:"VersionId"`
			IsDefaultVersion bool            `json:"IsDefaultVersion"`
		} `json:"PolicyVersionList"`
	} `json:"Policies"`
}

func parseAuthDetails(data []byte) (*Inventory, error) {
	var ad authDetails
	if err := json.Unmarshal(data, &ad); err != nil {
		return nil, fmt.Errorf("decode authorization details: %w", err)
	}
	managed := map[string]*policy.Document{}
	for _, mp := range ad.Policies {
		for _, v := range mp.PolicyVersionList {
			if !v.IsDefaultVersion && v.VersionID != mp.DefaultVersionID {
				continue
			}
			doc, err := decodeDocument(v.Document)
			if err != nil {
				return nil, fmt.Errorf("managed policy %s: %w", mp.Arn, err)
			}
			managed[mp.Arn] = doc
		}
	}
	type groupPolicies struct {
		docs     []NamedDoc
		warnings []string
	}
	groups := map[string]*groupPolicies{}
	resolve := func(owner string, list []attached, source string) ([]NamedDoc, []string) {
		var out []NamedDoc
		var warns []string
		for _, a := range list {
			doc, ok := managed[a.PolicyArn]
			if !ok {
				warns = append(warns, fmt.Sprintf("%s: attached managed policy %s not present in input; its permissions are not analysed", owner, a.PolicyArn))
				continue
			}
			out = append(out, NamedDoc{Name: a.PolicyName, Source: source, Doc: doc})
		}
		return out, warns
	}
	inline := func(owner string, list []inlinePolicy, source string) ([]NamedDoc, error) {
		var out []NamedDoc
		for _, ip := range list {
			doc, err := decodeDocument(ip.PolicyDocument)
			if err != nil {
				return nil, fmt.Errorf("%s inline policy %s: %w", owner, ip.PolicyName, err)
			}
			out = append(out, NamedDoc{Name: ip.PolicyName, Source: source, Doc: doc})
		}
		return out, nil
	}
	boundary := func(p *Principal, ref *boundaryRef) {
		if ref == nil || ref.PermissionsBoundaryArn == "" {
			return
		}
		doc, ok := managed[ref.PermissionsBoundaryArn]
		if !ok {
			p.Warnings = append(p.Warnings, fmt.Sprintf("permissions boundary %s not present in input; boundary ignored", ref.PermissionsBoundaryArn))
			return
		}
		p.Boundary = &NamedDoc{Name: ref.PermissionsBoundaryArn, Source: "boundary", Doc: doc}
	}
	for _, g := range ad.GroupDetailList {
		docs, err := inline(g.Arn, g.GroupPolicyList, "group "+g.GroupName+" inline")
		if err != nil {
			return nil, err
		}
		md, warns := resolve("group "+g.GroupName, g.AttachedManagedPolicies, "group "+g.GroupName+" managed")
		groups[g.GroupName] = &groupPolicies{docs: append(docs, md...), warnings: warns}
	}
	inv := &Inventory{}
	for _, u := range ad.UserDetailList {
		p := &Principal{ARN: u.Arn}
		docs, err := inline(u.Arn, u.UserPolicyList, "inline")
		if err != nil {
			return nil, err
		}
		md, warns := resolve("user", u.AttachedManagedPolicies, "managed")
		p.Policies = append(p.Policies, docs...)
		p.Policies = append(p.Policies, md...)
		p.Warnings = append(p.Warnings, warns...)
		for _, gn := range u.GroupList {
			g, ok := groups[gn]
			if !ok {
				p.Warnings = append(p.Warnings, fmt.Sprintf("group %s not present in input; its policies are not analysed", gn))
				continue
			}
			p.Policies = append(p.Policies, g.docs...)
			p.Warnings = append(p.Warnings, g.warnings...)
		}
		boundary(p, u.PermissionsBoundary)
		inv.Principals = append(inv.Principals, p)
	}
	for _, r := range ad.RoleDetailList {
		p := &Principal{ARN: r.Arn}
		docs, err := inline(r.Arn, r.RolePolicyList, "inline")
		if err != nil {
			return nil, err
		}
		md, warns := resolve("role", r.AttachedManagedPolicies, "managed")
		p.Policies = append(p.Policies, docs...)
		p.Policies = append(p.Policies, md...)
		p.Warnings = append(p.Warnings, warns...)
		boundary(p, r.PermissionsBoundary)
		inv.Principals = append(inv.Principals, p)
	}
	return inv, nil
}
