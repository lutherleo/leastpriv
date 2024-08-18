# Design decisions

Key design decisions in leastpriv, each with the reasoning and what it would cost if it turned out wrong, in the format
`<decision> — <why> — <cost if wrong>`.

## Scope

- Analyse identity-based policies plus permissions boundaries only; resource-based policies, SCPs/RCPs, session policies and cross-account trust are out of scope — they are the policies a principal's owner attaches and can right-size, and they are what CloudTrail activity can be attributed to — a call granted only by a bucket policy shows up as "used but not granted" instead of being modelled, so a team relying on resource policies sees noise in the report.
- Bundle a hand-curated catalog subset (12 services, 208 actions) instead of the full Service Authorization Reference — it keeps the tool offline, reviewable and small, and the CloudTrail event-name mapping has to be curated by hand anyway — events from services outside the catalog are counted and reported as ignored, so a real account using e.g. CloudFormation or RDS gets no policy for those calls.
- Pure Go standard library, no third-party modules — the domain needs JSON, gzip, net/netip and sorting, all in the stdlib; zero dependencies is also a supply-chain property worth having in a security tool — some code (glob matching, LCS diff) is hand-written instead of borrowed.
- `go.mod` declares `go 1.24` while CI and development use Go 1.27 — nothing newer than 1.24 is needed and a lower floor helps anyone building from source — a 1.27-only API used by mistake would be caught by CI only if CI also ran 1.24 (it does not).

- CI installs a pinned golangci-lint (v2.15.0) with `go install` on the latest Go 1.27 patch release — a pinned linter keeps `make check` reproducible, and building it with the same Go as the code avoids toolchain skew — the linter's type checker must understand the compiler's export data: Go 1.27.2 moved to export-data version 5, which golangci-lint v2.13.x (x/tools v0.49) cannot read, so every Go upgrade may need a linter bump.

## Evaluation engine

- Mirror AWS's documented evaluation order (explicit deny > identity allow ∩ boundary allow > implicit deny) and test it with a table that names the IAM User Guide section each case reproduces (67 cases) — documented behaviour is the only ground truth available offline — undocumented AWS edge cases (some operator/key type coercions) can differ; the Limitations section says so.
- Three-valued condition evaluation (yes / maybe / no) for keys whose value is unknown — CloudTrail does not record many context keys (resource and principal tags, `aws:SourceVpc`, `aws:CalledVia`, most service-specific keys), and guessing either way would make replay unsound — reports carry an "uncertain" count instead of a hard PASS/FAIL for such calls, which is less crisp.
- Support the documented Condition subset (String*, Numeric*, Date*, Bool, IpAddress/NotIpAddress, Arn*, Null, `...IfExists`, `ForAllValues:`/`ForAnyValue:`) and policy variables including `${*}`, `${?}`, `${$}` and defaults; reject unknown operators at compile time — rejecting is safer than silently ignoring a condition — policies using BinaryEquals or a future operator fail to load instead of being analysed.
- Version `2008-10-17` documents treat `${...}` literally, and the generator re-escapes such text when it emits 2012-10-17 output — otherwise upgrading the version would silently turn literal text into variables — none beyond extra escaping noise in rare policies.

## Generation

- Every generated grant is attributed to one original Allow statement and inherits its Condition block verbatim; original Deny statements are copied verbatim — this makes "generated ⊆ original" provable statement-by-statement instead of needing a global solver — the output can carry conditions that are redundant for the observed calls.
- Prove each emitted (action pattern, resource pattern) is inside its source statement with sound glob subsumption (a DP over both patterns), then re-check with a differential evaluation over a request universe — subsumption is the proof, the differential check guards against bugs in the proof code — the differential check is stride-sampled above 250,000 pairs per context, so it is evidence, not proof, on large inventories.
- Three aggressiveness levels: `exact` (no wildcards), `moderate` (bottom-up collapse of uniform folders with ≥ 3 children; default), `aggressive` (top-down subtree and name-prefix collapse with ≥ 2 siblings, plus read-only `svc:Verb*` action folding) — defenders need a dial between "breaks tomorrow" and "grants too much", and the held-out evaluation shows the trade-off per level — the defaults are tuned on one synthetic scenario only.
- Aggressive action folding only produces `svc:Verb*` when every catalog action it matches is List or Read — write and permissions-management wildcards are where over-grants hurt — real AWS may add new Write actions matching an existing `Get*` pattern after release; the catalog cannot see them.
- Never collapse a flat namespace root (queue, function, role names) to a bare `*`; a resource the mapper could only partially resolve becomes a resource-type-scoped pattern (e.g. `arn:aws:s3:::bucket/*`), never `*` — `*` is the over-grant the tool exists to remove — partially mapped calls get a broader-than-necessary resource.
- When a source statement's Resource/NotResource uses policy variables (`${aws:username}`), keep it verbatim instead of concretising it from observed values — concretising would widen the grant for other sessions where the variable resolves differently — those statements are narrowed by action only.
- Exactly mapped resource names are treated as literals end to end and rendered with IAM's `${*}` / `${?}` / `${$}` escapes; partially mapped ones keep `*` for unknown parts — an S3 key may contain `*`, `?` or `${`, and emitting it verbatim widened the grant or broke replay — a literal `*` inside the known part of a partially mapped resource is still read as a wildcard (bounded by the source statement).
- When a partially mapped resource cannot be proved inside its source statement, the grant falls back to the source's own Resource/NotResource element, and text copied from a `2008-10-17` source is escaped (`${` → `${$}{`) exactly like copied Deny statements and conditions — the output is always `2012-10-17`, where an unescaped `${aws:username}` becomes a live variable and widens the grant (a focused property test now drives this path because the general random pools almost never reach it) — the fallback is still broader than the observed calls, and is listed under "fallbacks" in the report.
- Default split size 6,144 characters (whitespace excluded), the managed-policy limit, with first-fit packing into `partN` documents — identity policies combine by union and denies apply across documents, so the split is semantically neutral — inline-policy limits (2,048 for users) are stricter; users pass `--max-size`.

## Reporting

- "Granted" in the gap report is an upper bound that assumes conditions are satisfiable — a condition the tool cannot evaluate must not hide a grant from the reviewer — conditional grants are reported as granted even if no real request could satisfy them.
- Actions that produce no CloudTrail event, or only data events, are labelled `unobservable` or annotated "confirm data events were enabled" rather than `unused` — calling them unused would recommend removing permissions the tool cannot see being used — the user has to decide those by hand.
- Role paths are ignored when matching CloudTrail principals to the inventory (account + kind + name) — assumed-role session ARNs drop the path and role names are unique per account — none known.
- Distinct exit codes (0 ok, 1 error, 2 usage, 3 verification failed, 4 invalid policy) — lets CI pipelines gate on verification separately from crashes — none.
- `generate --out` also writes the input policies to `original/<stem>.<n>.json` — the before file is needed to run `leastpriv diff` in a change review, and extracting it from `get-account-authorization-details` by hand is error-prone — slightly more files in the output directory.

## Data and evaluation

- All fixtures are synthetic, generated deterministically by `lp-synth` (seed 20260701) and committed (≈1.1 MB gzipped); `make fixtures` must reproduce them byte-for-byte (CI checks this) — no public CloudTrail dataset with matching IAM policies and ground truth exists, and real logs would contain account data — results describe how the tool behaves on one designed scenario, not on real workloads.
- Evaluate with a temporal split (train on the first 60 days, score on the held-out last 30) and report every level, including the ones that look bad — tuning and scoring on the same window would hide over-fitting, which is exactly the failure mode of activity-based policy generation — none.
- `make integration` is an explicit no-op that says so — every test is offline and runs in `make test`, and a target that prints why there is nothing to run is clearer than a missing one for anyone (or any pipeline) that expects it — none.
