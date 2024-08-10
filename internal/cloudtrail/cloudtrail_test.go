package cloudtrail

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const roleRecord = `{"eventVersion":"1.09","eventTime":"2026-07-01T10:00:00Z","eventSource":"s3.amazonaws.com","eventName":"ListObjects","awsRegion":"us-east-1",
"sourceIPAddress":"10.0.0.5","userAgent":"sdk","eventID":"e1","recipientAccountId":"111122223333",
"userIdentity":{"type":"AssumedRole","principalId":"AROA1:s","arn":"arn:aws:sts::111122223333:assumed-role/app/s","accountId":"111122223333",
 "sessionContext":{"attributes":{"mfaAuthenticated":"false"},"sessionIssuer":{"type":"Role","arn":"arn:aws:iam::111122223333:role/svc/app"}}},
"requestParameters":{"bucketName":"b","prefix":"logs/","max-keys":100},"tlsDetails":{"tlsVersion":"TLSv1.3"}}`

func TestReadForms(t *testing.T) {
	dir := t.TempDir()
	wrapper := `{"Records":[` + roleRecord + `,` + roleRecord + `]}`
	jsonl := "\xef\xbb\xbf" + strings.ReplaceAll(roleRecord, "\n", "") + "\n" + strings.ReplaceAll(roleRecord, "\n", "") + "\n"
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte(wrapper))
	_ = w.Close()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "sub"), 0o750))
	must(os.WriteFile(filepath.Join(dir, "a.json"), []byte(wrapper), 0o600))
	must(os.WriteFile(filepath.Join(dir, "sub", "b.jsonl"), []byte(jsonl), 0o600))
	must(os.WriteFile(filepath.Join(dir, "sub", "c.json.gz"), gz.Bytes(), 0o600))
	must(os.WriteFile(filepath.Join(dir, "README.txt"), []byte("ignored"), 0o600))
	must(os.WriteFile(filepath.Join(dir, "empty.json"), []byte("  \n"), 0o600))
	recs, err := ReadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 6 {
		t.Fatalf("want 6 records, got %d", len(recs))
	}
	// Single file path.
	recs, err = ReadAll(filepath.Join(dir, "sub", "c.json.gz"))
	if err != nil || len(recs) != 2 {
		t.Fatalf("gz file: %d %v", len(recs), err)
	}
	// Early stop.
	n := 0
	err = ReadPath(dir, func(Record) error {
		n++
		if n == 3 {
			return ErrStop
		}
		return nil
	})
	if err != nil || n != 3 {
		t.Fatalf("stop: n=%d err=%v", n, err)
	}
	err = ReadPath(filepath.Join(dir, "a.json"), func(Record) error { return ErrStop })
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	if err := ReadPath(dir, func(Record) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("visitor error not propagated: %v", err)
	}
	if _, err := ReadAll(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing path")
	}
}

func TestReadErrors(t *testing.T) {
	bad := []string{
		`[1,2]`,
		`{"Records":{}}`,
		`{"Records":[1]}`,
		`{"Records":[]} trailing`,
		`{"Records":[]} {"x":1}`,
		`{"eventTime":1}`,
		`{"eventName":"a"} [`,
		`{"eventName":"a"} {"eventTime":5}`,
		`{"Records":[{"eventTime":5}]}`,
	}
	for _, b := range bad {
		if err := Read(strings.NewReader(b), func(Record) error { return nil }); err == nil {
			t.Errorf("expected error for %q", b)
		}
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json.gz")
	if err := os.WriteFile(p, []byte{0x1f, 0x8b, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReadFile(p, func(Record) error { return nil }); err == nil {
		t.Fatal("corrupt gzip accepted")
	}
}

func parse(t *testing.T, js string) Record {
	t.Helper()
	var recs []Record
	if err := Read(strings.NewReader(js), func(r Record) error { recs = append(recs, r); return nil }); err != nil || len(recs) != 1 {
		t.Fatalf("parse: %v", err)
	}
	return recs[0]
}

func TestPrincipalAndContext(t *testing.T) {
	r := parse(t, roleRecord)
	p, ok, _ := r.PrincipalARN()
	if !ok || p != "arn:aws:iam::111122223333:role/svc/app" {
		t.Fatalf("principal %s", p)
	}
	ctx := r.Context(p)
	want := map[string]string{
		"aws:sourceip": "10.0.0.5", "aws:requestedregion": "us-east-1", "aws:principaltype": "AssumedRole",
		"aws:multifactorauthpresent": "false", "aws:securetransport": "true", "aws:viaawsservice": "false",
		"s3:prefix": "logs/", "s3:max-keys": "100", "aws:currenttime": "2026-07-01T10:00:00Z", "aws:epochtime": "1782900000",
	}
	for k, v := range want {
		if got := ctx[k]; len(got) != 1 || got[0] != v {
			t.Errorf("%s=%v want %s", k, got, v)
		}
	}
	if !r.Succeeded() || r.Denied() || r.Account() != "111122223333" {
		t.Fatal("status helpers")
	}
	if r.IsUnknownKey("aws:SourceIp") || !r.IsUnknownKey("aws:ResourceTag/env") || r.IsUnknownKey("aws:SecureTransport") {
		t.Fatal("IsUnknownKey")
	}
	old := parse(t, `{"eventVersion":"1.05","eventTime":"2026-07-01T10:00:00Z","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::1:user/u","userName":"u","accountId":"1","invokedBy":"cloudformation.amazonaws.com"},"errorCode":"AccessDenied"}`)
	if !old.IsUnknownKey("aws:securetransport") {
		t.Fatal("TLS key must be unknown for old records")
	}
	octx := old.Context("arn:aws:iam::1:user/u")
	if octx["aws:username"][0] != "u" || octx["aws:viaawsservice"][0] != "true" || octx["aws:principaltype"][0] != "User" {
		t.Fatalf("user context %v", octx)
	}
	if _, has := octx["aws:securetransport"]; has {
		t.Fatal("old record must not assert SecureTransport")
	}
	if !old.Denied() || old.Succeeded() || old.Account() != "1" {
		t.Fatal("denied helpers")
	}
	newNoTLS := parse(t, `{"eventVersion":"1.09","eventTime":"2026-07-01T10:00:00Z","userIdentity":{"type":"Root","arn":"arn:aws:iam::1:root","accountId":"1"}}`)
	if newNoTLS.Context("arn:aws:iam::1:root")["aws:securetransport"][0] != "false" {
		t.Fatal("new record without tlsDetails means no TLS")
	}
}

func TestPrincipalVariants(t *testing.T) {
	cases := []struct {
		identity string
		want     string
		ok       bool
	}{
		{`{"type":"IAMUser","arn":"arn:aws:iam::1:user/a/b"}`, "arn:aws:iam::1:user/a/b", true},
		{`{"type":"IAMUser"}`, "", false},
		{`{"type":"Root","arn":"arn:aws:iam::1:root"}`, "arn:aws:iam::1:root", true},
		{`{"type":"AssumedRole","arn":"arn:aws:sts::1:assumed-role/deploy/sess"}`, "arn:aws:iam::1:role/deploy", true},
		{`{"type":"AssumedRole","arn":"arn:aws:sts::1:federated-user/x"}`, "", false},
		{`{"type":"AssumedRole","arn":"garbage"}`, "", false},
		{`{"type":"AWSService","invokedBy":"lambda.amazonaws.com"}`, "", false},
		{`{"type":"AWSAccount","accountId":"2"}`, "", false},
		{`{}`, "", false},
		{`{"type":"WebIdentityUser","sessionContext":{"sessionIssuer":{"arn":"arn:aws:iam::1:role/oidc"}}}`, "arn:aws:iam::1:role/oidc", true},
		{`{"type":"SAMLUser"}`, "", false},
	}
	for _, c := range cases {
		r := parse(t, `{"eventTime":"2026-07-01T00:00:00Z","userIdentity":`+c.identity+`}`)
		got, ok, reason := r.PrincipalARN()
		if got != c.want || ok != c.ok || (!ok && reason == "") {
			t.Errorf("%s: got %q %v %q", c.identity, got, ok, reason)
		}
	}
	bad := parse(t, `{"eventTime":"yesterday"}`)
	if _, err := bad.Time(); err == nil {
		t.Fatal("bad time accepted")
	}
	if len(bad.Context("x")["aws:currenttime"]) != 0 {
		t.Fatal("context from bad time")
	}
}
