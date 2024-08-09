#!/usr/bin/env bash
# Offline end-to-end demo against the bundled synthetic account
# (testdata/acme: fictional account 111122223333, 90 days of CloudTrail).
# Nothing here contacts AWS. Outputs land in out/demo/.
set -euo pipefail
cd "$(dirname "$0")/.."

LP=./bin/leastpriv
AUTHZ=testdata/acme/authz.json
TRAIL=testdata/acme/cloudtrail
OUT=out/demo
APP=arn:aws:iam::111122223333:role/app/app-backend
CI=arn:aws:iam::111122223333:role/ci-deployer
DECOY=arn:aws:s3:::acme-app-data/admin/break-glass.txt

rm -rf "$OUT"
mkdir -p "$OUT"

step() { printf '\n==> %s\n$ %s\n' "$1" "$2"; }

step "1. Map CloudTrail records to IAM actions and resource ARNs" \
	"leastpriv map --trail $TRAIL --limit 5"
$LP map --trail "$TRAIL" --limit 5

step "2. Permission-gap report for the CI role (granted vs used, last-used age)" \
	"leastpriv gap --authz $AUTHZ --trail $TRAIL --principal $CI --out $OUT/gap"
$LP gap --authz "$AUTHZ" --trail "$TRAIL" --principal "$CI" --out "$OUT/gap" | sed -n '1,6p'
echo "   (full report: $OUT/gap/gap.md, machine-readable: $OUT/gap/gap.json)"

step "3. Generate, verify and diff minimal policies for every principal (moderate)" \
	"leastpriv generate --authz $AUTHZ --trail $TRAIL --level moderate --out $OUT/policies"
$LP generate --authz "$AUTHZ" --trail "$TRAIL" --level moderate --out "$OUT/policies" | sed -n '1,13p'
echo "   (per-principal sections, wildcards introduced and skipped calls: $OUT/policies/report.md)"

step "4. The generated policy for app-backend" \
	"cat $OUT/policies/role-app-backend.policy.json | head -30"
head -30 "$OUT/policies/role-app-backend.policy.json"
echo "   ..."

step "5. Before/after diff for the CI role (effective, per action)" \
	"leastpriv diff $OUT/policies/original/role-ci-deployer.1.json $OUT/policies/role-ci-deployer.policy.json"
$LP diff "$OUT/policies/original/role-ci-deployer.1.json" "$OUT/policies/role-ci-deployer.policy.json" | sed -n '1,8p'

step "6. A sensitive decoy object: allowed by the original grant, denied by the generated one" \
	"leastpriv simulate --authz $AUTHZ --principal $APP --action s3:GetObject --resource $DECOY"
$LP simulate --authz "$AUTHZ" --principal "$APP" --action s3:GetObject --resource "$DECOY" || true
printf '$ %s\n' "leastpriv simulate --policy $OUT/policies/role-app-backend.policy.json --action s3:GetObject --resource $DECOY"
$LP simulate --policy "$OUT/policies/role-app-backend.policy.json" --action s3:GetObject --resource "$DECOY" || true

step "7. Independent re-verification of a generated policy" \
	"leastpriv verify --authz $AUTHZ --trail $TRAIL --principal $APP --policy $OUT/policies/role-app-backend.policy.json"
$LP verify --authz "$AUTHZ" --trail "$TRAIL" --principal "$APP" --policy "$OUT/policies/role-app-backend.policy.json" | sed -n '1,3p'

step "8. Held-out evaluation against ground truth (train 60 days, test the last 30)" \
	"lp-eval --data testdata/acme --out $OUT/eval"
./bin/lp-eval --data testdata/acme --out "$OUT/eval" | sed -n '1,20p'

printf '\nDemo complete. Artifacts in %s/\n' "$OUT"
