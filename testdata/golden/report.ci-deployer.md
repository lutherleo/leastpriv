# Least-privilege policy report

Level: `moderate`. Input: 9561 CloudTrail records, 9870 observations, 14 access-denied attempts, 30 records from non-principal callers, window 2026-07-01 to 2026-09-28.

Events from services outside the catalog (ignored): cloudformation.amazonaws.com x45.

| Principal | Distinct calls | Granted | Statements | Size (chars) | Replay | Subset check |
|---|---:|---:|---:|---:|---|---|
| `arn:aws:iam::111122223333:role/ci-deployer` | 270 | 270 | 4 | 1443 | 726/726 allowed | 0 violations in 78000 requests |

## `arn:aws:iam::111122223333:role/ci-deployer`

Effective change vs. original: 200 removed, 8 narrowed, 0 widened, 0 added, 0 changed (statements 2 -> 4, size 316 -> 1443 chars).

Verification: **PASS**. Replay: 726 of 726 observed calls the original allows are allowed (0 uncertain). Differential check: 78000 requests over 208 actions x 375 resources x 4 contexts, 528 allowed by the generated policy, 0 violations (stride-sampled).

| Sid | Actions | Resources | Condition | Derived from |
|---|---|---|---|---|
| AllowLambda | `lambda:CreateFunction`, `lambda:DeleteFunction` | `arn:aws:lambda:us-east-1:111122223333:function:deploy-reports` | `{"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}` | CiDeployerAccess/AdminInDeployRegions |
| AllowLambdaN2 | `lambda:GetFunction` | `arn:aws:lambda:us-east-1:111122223333:function:deploy-api`, `arn:aws:lambda:us-east-1:111122223333:function:deploy-cron`, `arn:aws:lambda:us-east-1:111122223333:function:deploy-worker`, `arn:aws:lambda:us-west-2:111122223333:function:deploy-api`, +2 more | `{"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}` | CiDeployerAccess/AdminInDeployRegions |
| AllowLambdaN3 | `lambda:PublishVersion`, `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration` | `arn:aws:lambda:us-east-1:111122223333:function:deploy-api`, `arn:aws:lambda:us-east-1:111122223333:function:deploy-cron`, `arn:aws:lambda:us-east-1:111122223333:function:deploy-worker` | `{"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}` | CiDeployerAccess/AdminInDeployRegions |
| AllowS3 | `s3:GetObject`, `s3:PutObject` | `arn:aws:s3:::acme-artifacts/builds/*` | `{"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}` | CiDeployerAccess/AdminInDeployRegions |

Wildcards introduced (2 collapses):

- `arn:aws:s3:::acme-artifacts/builds/*` for `s3:GetObject` replaces 128 observed resources (path)
- `arn:aws:s3:::acme-artifacts/builds/*` for `s3:PutObject` replaces 125 observed resources (path)

Skipped observations:

- `sts:GetCallerIdentity` on `*` x64: action requires no IAM permission
