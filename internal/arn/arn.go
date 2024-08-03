// Package arn parses Amazon Resource Names and implements the resource
// matching rules used by IAM policy evaluation.
//
// An ARN has six colon-separated parts: arn:partition:service:region:account:resource.
// The resource part may itself contain colons and slashes. IAM resource
// patterns may use '*' and '?' in any segment; wildcards in the partition,
// service, region and account segments never cross a colon, while the
// resource segment is matched as a whole string. A bare "*" matches every
// resource, including the resource-less "*" used by actions that do not
// support resource-level permissions.
package arn

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lutherleo/leastpriv/internal/glob"
)

// ARN is a parsed Amazon Resource Name.
type ARN struct {
	Partition string
	Service   string
	Region    string
	Account   string
	Resource  string
}

// ErrNotARN is returned when a string does not have the arn: prefix and six parts.
var ErrNotARN = errors.New("not an ARN")

// Parse splits s into its ARN components.
func Parse(s string) (ARN, error) {
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return ARN{}, fmt.Errorf("%w: %q", ErrNotARN, s)
	}
	return ARN{Partition: parts[1], Service: parts[2], Region: parts[3], Account: parts[4], Resource: parts[5]}, nil
}

// String renders the ARN.
func (a ARN) String() string {
	return "arn:" + a.Partition + ":" + a.Service + ":" + a.Region + ":" + a.Account + ":" + a.Resource
}

// PartitionForRegion returns the AWS partition that owns region.
func PartitionForRegion(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	default:
		return "aws"
	}
}

func split6(s string) ([]string, bool) {
	parts := strings.SplitN(s, ":", 6)
	return parts, len(parts) == 6
}

// Match reports whether a concrete resource (or "*") matches an IAM resource
// pattern. Matching is case-sensitive, as in IAM.
func Match(pattern, resource string) bool {
	if pattern == "*" {
		return true
	}
	pp, okP := split6(pattern)
	rp, okR := split6(resource)
	if !okP || !okR {
		return glob.Match(pattern, resource)
	}
	for i := 0; i < 6; i++ {
		if !glob.Match(pp[i], rp[i]) {
			return false
		}
	}
	return true
}

// Subsumes reports whether every resource matched by pattern specific is also
// matched by pattern general. Like glob.Subsumes it is sound but incomplete.
func Subsumes(general, specific string) bool {
	if general == "*" {
		return true
	}
	gp, okG := split6(general)
	sp, okS := split6(specific)
	if !okG || !okS {
		return glob.Subsumes(general, specific)
	}
	for i := 0; i < 6; i++ {
		// A '*' in a non-resource segment of specific cannot cross a colon,
		// so segment-wise inclusion is exact for those segments.
		if !glob.Subsumes(gp[i], sp[i]) {
			return false
		}
	}
	return true
}

// IsPattern reports whether s contains IAM wildcards.
func IsPattern(s string) bool { return glob.HasWildcard(s) }
