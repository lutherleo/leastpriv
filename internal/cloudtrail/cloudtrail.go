// Package cloudtrail reads AWS CloudTrail log files and derives, for each
// record, the calling IAM principal and the IAM condition context that can
// be reconstructed from the log.
//
// Supported inputs: CloudTrail log files ({"Records":[...]}, optionally
// gzip-compressed as delivered to S3), JSON Lines with one record per line,
// and directories of either (walked recursively in lexical order). Files are
// decoded one at a time and records are handed to a visitor, so memory use
// is bounded by the largest single file plus what the caller retains.
package cloudtrail

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/lutherleo/leastpriv/internal/arn"
)

// Record is one CloudTrail event record (the fields this tool uses).
type Record struct {
	EventVersion       string         `json:"eventVersion"`
	EventTime          string         `json:"eventTime"`
	EventSource        string         `json:"eventSource"`
	EventName          string         `json:"eventName"`
	AWSRegion          string         `json:"awsRegion"`
	SourceIPAddress    string         `json:"sourceIPAddress"`
	UserAgent          string         `json:"userAgent"`
	ErrorCode          string         `json:"errorCode,omitempty"`
	ErrorMessage       string         `json:"errorMessage,omitempty"`
	EventID            string         `json:"eventID"`
	EventType          string         `json:"eventType"`
	ReadOnly           *bool          `json:"readOnly,omitempty"`
	RecipientAccountID string         `json:"recipientAccountId"`
	VPCEndpointID      string         `json:"vpcEndpointId,omitempty"`
	UserIdentity       UserIdentity   `json:"userIdentity"`
	RequestParameters  map[string]any `json:"requestParameters"`
	Resources          []Resource     `json:"resources,omitempty"`
	TLSDetails         *TLSDetails    `json:"tlsDetails,omitempty"`
}

// UserIdentity is the userIdentity element.
type UserIdentity struct {
	Type           string          `json:"type"`
	PrincipalID    string          `json:"principalId"`
	ARN            string          `json:"arn"`
	AccountID      string          `json:"accountId"`
	AccessKeyID    string          `json:"accessKeyId,omitempty"`
	UserName       string          `json:"userName,omitempty"`
	InvokedBy      string          `json:"invokedBy,omitempty"`
	SessionContext *SessionContext `json:"sessionContext,omitempty"`
}

// SessionContext describes temporary-credential sessions.
type SessionContext struct {
	Attributes struct {
		MFAAuthenticated string `json:"mfaAuthenticated"`
		CreationDate     string `json:"creationDate"`
	} `json:"attributes"`
	SessionIssuer struct {
		Type        string `json:"type"`
		PrincipalID string `json:"principalId"`
		ARN         string `json:"arn"`
		AccountID   string `json:"accountId"`
		UserName    string `json:"userName"`
	} `json:"sessionIssuer"`
}

// Resource is an element of the resources array.
type Resource struct {
	ARN       string `json:"ARN"`
	AccountID string `json:"accountId"`
	Type      string `json:"type"`
}

// TLSDetails is present when the request used TLS.
type TLSDetails struct {
	TLSVersion  string `json:"tlsVersion"`
	CipherSuite string `json:"cipherSuite"`
}

// Time parses eventTime.
func (r *Record) Time() (time.Time, error) {
	t, err := time.Parse(time.RFC3339, r.EventTime)
	if err != nil {
		return time.Time{}, fmt.Errorf("event %s: bad eventTime %q: %w", r.EventID, r.EventTime, err)
	}
	return t.UTC(), nil
}

// Succeeded reports whether the call was authorized and completed. Records
// with an errorCode are failures; access-denied failures are classified by
// Denied.
func (r *Record) Succeeded() bool { return r.ErrorCode == "" }

// Denied reports whether the record is an authorization failure.
func (r *Record) Denied() bool {
	switch r.ErrorCode {
	case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "Client.UnauthorizedOperation", "AuthorizationError":
		return true
	}
	return false
}

// Account returns the account the request was made to.
func (r *Record) Account() string {
	if r.RecipientAccountID != "" {
		return r.RecipientAccountID
	}
	return r.UserIdentity.AccountID
}

// PrincipalARN returns the IAM principal (user or role ARN) that made the
// call, normalising assumed-role sessions to their role. ok is false for
// callers that are not IAM principals of this account (AWS services,
// anonymous callers) or that cannot be attributed.
func (r *Record) PrincipalARN() (principal string, ok bool, reason string) {
	id := r.UserIdentity
	switch id.Type {
	case "IAMUser", "Root":
		if id.ARN == "" {
			return "", false, "identity has no ARN"
		}
		return id.ARN, true, ""
	case "AssumedRole":
		if sc := id.SessionContext; sc != nil && sc.SessionIssuer.ARN != "" {
			return sc.SessionIssuer.ARN, true, ""
		}
		return roleFromAssumedRole(id.ARN)
	case "AWSService":
		return "", false, "call made by an AWS service principal"
	case "AWSAccount":
		return "", false, "cross-account caller without an attributable principal"
	case "":
		return "", false, "record has no userIdentity type"
	default:
		if sc := id.SessionContext; sc != nil && sc.SessionIssuer.ARN != "" {
			return sc.SessionIssuer.ARN, true, ""
		}
		return "", false, "unsupported identity type " + id.Type
	}
}

// roleFromAssumedRole converts arn:aws:sts::ACCT:assumed-role/NAME/SESSION to
// arn:aws:iam::ACCT:role/NAME. The role path is not recorded in the session
// ARN, so principals are matched by account and role name.
func roleFromAssumedRole(s string) (string, bool, string) {
	a, err := arn.Parse(s)
	if err != nil {
		return "", false, "unparseable assumed-role ARN"
	}
	rest, found := strings.CutPrefix(a.Resource, "assumed-role/")
	if !found {
		return "", false, "unexpected assumed-role ARN " + s
	}
	name, _, _ := strings.Cut(rest, "/")
	return arn.ARN{Partition: a.Partition, Service: "iam", Account: a.Account, Resource: "role/" + name}.String(), true, ""
}

// DerivableKeys are the global condition keys this package can reconstruct
// from a CloudTrail record. When one of them is absent from a derived
// context it is authoritatively absent; every other key is unknown.
var DerivableKeys = map[string]bool{
	"aws:currenttime":            true,
	"aws:epochtime":              true,
	"aws:sourceip":               true,
	"aws:requestedregion":        true,
	"aws:principalarn":           true,
	"aws:principalaccount":       true,
	"aws:principaltype":          true,
	"aws:userid":                 true,
	"aws:username":               true,
	"aws:multifactorauthpresent": true,
	"aws:useragent":              true,
	"aws:viaawsservice":          true,
	"aws:sourcevpce":             true,
	"s3:prefix":                  true,
	"s3:delimiter":               true,
	"s3:max-keys":                true,
}

// IsUnknownKey reports whether an absent key is unknown for this record's
// derived context (suitable as engine.Request.Unknown). aws:SecureTransport
// is derivable only from records new enough to carry tlsDetails.
func (r *Record) IsUnknownKey(key string) bool {
	key = strings.ToLower(key)
	if key == "aws:securetransport" {
		return r.TLSDetails == nil && r.EventVersion < "1.08"
	}
	return !DerivableKeys[key]
}

// Context derives IAM condition-context keys from the record. principal is
// the normalised principal ARN from PrincipalARN.
func (r *Record) Context(principal string) map[string][]string {
	ctx := map[string][]string{}
	set := func(k, v string) {
		if v != "" {
			ctx[k] = []string{v}
		}
	}
	if t, err := r.Time(); err == nil {
		set("aws:currenttime", t.Format(time.RFC3339))
		set("aws:epochtime", strconv.FormatInt(t.Unix(), 10))
	}
	if ip, err := netip.ParseAddr(r.SourceIPAddress); err == nil {
		set("aws:sourceip", ip.String())
	}
	set("aws:requestedregion", r.AWSRegion)
	set("aws:principalarn", principal)
	set("aws:principalaccount", r.UserIdentity.AccountID)
	set("aws:userid", r.UserIdentity.PrincipalID)
	set("aws:useragent", r.UserAgent)
	set("aws:sourcevpce", r.VPCEndpointID)
	switch r.UserIdentity.Type {
	case "IAMUser":
		set("aws:principaltype", "User")
		set("aws:username", r.UserIdentity.UserName)
	case "AssumedRole":
		set("aws:principaltype", "AssumedRole")
	case "Root":
		set("aws:principaltype", "Account")
	}
	if sc := r.UserIdentity.SessionContext; sc != nil && sc.Attributes.MFAAuthenticated != "" {
		set("aws:multifactorauthpresent", strings.ToLower(sc.Attributes.MFAAuthenticated))
	}
	if r.TLSDetails != nil {
		set("aws:securetransport", "true")
	} else if r.EventVersion >= "1.08" {
		// tlsDetails is recorded from event version 1.08 onwards; its
		// absence on newer records means the request was not over TLS.
		set("aws:securetransport", "false")
	}
	if r.UserIdentity.InvokedBy != "" && strings.HasSuffix(r.UserIdentity.InvokedBy, ".amazonaws.com") {
		set("aws:viaawsservice", "true")
	} else {
		set("aws:viaawsservice", "false")
	}
	if r.EventSource == "s3.amazonaws.com" {
		for _, k := range []string{"prefix", "delimiter", "max-keys"} {
			if v, ok := r.RequestParameters[k]; ok {
				set("s3:"+k, fmt.Sprint(v))
			}
		}
	}
	return ctx
}
