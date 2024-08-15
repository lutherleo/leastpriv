package generator

import (
	"fmt"
	"testing"

	"github.com/lutherleo/leastpriv/internal/activity"
)

// BenchmarkGenerateScaling measures end-to-end generation (attribution,
// grouping, collapsing, assembly) as the number of distinct observations
// grows. docs/ARCHITECTURE.md quotes these numbers; see scripts/bench.sh.
func BenchmarkGenerateScaling(b *testing.B) {
	p := principal(b, "", doc(`{"Effect":"Allow","Action":["s3:Get*","s3:PutObject","s3:ListBucket"],"Resource":"*"},`+
		`{"Effect":"Allow","Action":["dynamodb:GetItem","dynamodb:Query"],"Resource":"arn:aws:dynamodb:us-east-1:111122223333:table/*"},`+
		`{"Effect":"Allow","Action":"sqs:*","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}},`+
		`{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}`))
	for _, n := range []int{1_000, 10_000, 100_000} {
		observations := make([]activity.Observation, 0, n)
		for i := 0; i < n; i++ {
			var o activity.Observation
			switch i % 4 {
			case 0:
				o = obs("s3:GetObject", fmt.Sprintf("arn:aws:s3:::bucket-%d/tenant-%d/day-%d/obj-%d.json", i%7, i%50, i%90, i))
			case 1:
				o = obs("s3:PutObject", fmt.Sprintf("arn:aws:s3:::bucket-%d/tenant-%d/out/%d.csv", i%7, i%50, i))
			case 2:
				o = obs("dynamodb:Query", fmt.Sprintf("arn:aws:dynamodb:us-east-1:111122223333:table/t%d/index/i%d", i%40, i%3))
			default:
				o = obs("sqs:SendMessage", fmt.Sprintf("arn:aws:sqs:us-east-1:111122223333:q-%d", i%200), "aws:RequestedRegion", "us-east-1")
			}
			observations = append(observations, o)
		}
		for _, level := range []Level{LevelExact, LevelModerate, LevelAggressive} {
			b.Run(fmt.Sprintf("obs=%d/%s", n, level), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if _, err := Generate(cat, Input{Principal: p, Observations: observations}, Options{Level: level}); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
