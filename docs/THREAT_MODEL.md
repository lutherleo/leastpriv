# Threat model

leastpriv is a defensive, offline analysis tool. It reads IAM policy
documents and CloudTrail logs that an operator already holds and writes
proposed policies and reports. It never calls AWS, never applies a policy,
and has no network code.

## Who uses it, and for what

- **Cloud security / platform engineers** right-sizing over-broad roles and
  users after a workload has run for a while.
- **Reviewers** of an IAM change who want an effective (per-action) diff and
  a verification that the new policy still allows what the workload did.
- **Auditors** who need a granted-vs-used report with last-used ages.

## Assets

| Asset | Why it matters |
|---|---|
| The proposed policy | If it is broader than the original it *adds* privilege; if it is narrower than real use it causes an outage, which pushes teams back to `*`. |
| The inputs (IAM inventory, CloudTrail) | Contain account IDs, principal names, resource names, source IPs, user agents. Sensitive even without credentials. |
| The reports | Summarise who can do what and which grants are unused: useful to an attacker as reconnaissance. |

## Trust boundaries and threats

| # | Threat | Mitigation in leastpriv | Residual risk |
|---|---|---|---|
| T1 | **Privilege escalation through the generator**: a bug makes the generated policy allow something the original did not. | Every emitted pattern must be proved inside its source statement by sound subsumption; conditions and Denies are copied verbatim; boundary unchanged. `verify` re-checks with a differential evaluation over a probe universe; a property test checks `observed ⊆ generated ⊆ original` over 400 random policy/activity cases per level. Exit code 3 on any violation. | The differential check is sampled above 250k pairs per context; the engine models documented semantics only. |
| T2 | **Poisoned activity widens the policy**: an attacker who controls a principal makes calls so the generated policy keeps (or collapses toward) permissions they want. | Generation can never exceed the original grant (T1), so poisoning cannot add privilege; it can only keep privilege that would otherwise be removed. Collapse thresholds and the `exact` level limit how far a few planted calls generalise. Wildcards introduced are listed with how many observed resources each replaces, for review. | An attacker already holding a permission can keep it in the right-sized policy by exercising it. Review "wildcards introduced" and the gap report. |
| T3 | **Log tampering / gaps**: missing data events, deleted trails, or truncated windows make needed permissions look unused. | Data-event-only actions are flagged; unobservable actions are never labelled `unused`; the report shows the observation window and record counts; the eval measures breakage on a held-out month. | leastpriv cannot detect a deleted or filtered log. Use an organisation trail with log-file validation and a window covering monthly/quarterly jobs. |
| T4 | **Malformed or hostile input files** (huge JSON, deep nesting, invalid UTF-8, gzip bombs). | Strict decoding with unknown-element rejection for policies; one log file decoded at a time; errors are reported per file with exit code 1; a fuzz target covers the wildcard matcher. | A single very large log file is held in memory while decoded. No explicit decompression ratio limit. |
| T5 | **Wildcard injection via request data** (an object key containing `*` becoming part of a pattern). | Policy-variable substitution escapes substituted text. Exactly mapped resource names are carried internally as escaped literals and emitted with IAM's literal escapes (`x*y` → `x${*}y`, `q?` → `q${?}`, `${` → `${$}{`), covered by a regression test and the property-test pool. | Partially mapped resources use `*` for unknown ARN parts by design; a literal `*` in the *known* part of such a resource is not distinguished. |
| T6 | **Over-trusting "unused"**: removing a permission used by a rare job outside the window. | `stale` vs `unused` distinction with configurable age; held-out evaluation quantifies breakage per level; the `exact`/`moderate`/`aggressive` dial. | Inherent to activity-based right-sizing; the README's Limitations section states it. |
| T7 | **Disclosure of reports**. | Outputs are written with mode `0600` (directories `0750`); nothing leaves the machine. | Operators must handle reports as sensitive. |

## Non-goals

- Applying policies, calling IAM Access Analyzer or any AWS API.
- Detecting attacks in CloudTrail (that is a detection tool's job).
- Modelling resource-based policies, SCPs/RCPs, session policies or
  cross-account trust.

## Ethics

All bundled data is synthetic (fictional account `111122223333`,
documentation IP ranges). The tool only narrows permissions; it contains no
offensive capability, no credential handling and no network access.
