# Test fixtures for "Analyze Your Own Files"

50 files across the 4 upload slots on the Overview page's "Analyze Your Own Files" tab, covering
the real sub-formats each slot's own `FILE_HELP` panel (in `ui_render.py`) claims to accept. Every
vulnerable/CVE-bearing fixture cites a real CVE ID; every misconfiguration fixture targets a real
Trivy check ID, so uploading one produces a genuine finding, not an invented one.

Upload any file solo (all 4 slots are optional and fall back to the bundled `data/` sample if
left blank), or mix several at once. With 50 files across 4 independent slots, exhaustive
combination testing isn't practical — prefer one pass uploading each file individually to confirm
its expected result, plus a few deliberate multi-slot combos (all-clean, all-adversarial, one
boundary-focused run).

## `log/` — 13 files (`agents/log_monitor.py`)

| File | Expected result |
|---|---|
| `auth_clean.log` | No findings |
| `auth_multi_severity.log` | SSH brute force (CRITICAL) + privileged password login (HIGH) + `chmod 777` (MEDIUM) |
| `auth_boundary_2fails.log` | Exactly 2 failed logins — must NOT trigger brute-force (threshold is 3) |
| `auth_nonascii.log` | Contains a raw non-UTF-8 byte — must parse without crashing |
| `ufw_clean.log` | No port-scan finding (no IP has 3+ blocked ports) |
| `ufw_portscan_multi.log` | Port scan (HIGH) — one IP, 5 distinct blocked ports |
| `ufw_boundary_2ports.log` | Exactly 2 blocked ports — must NOT trigger (threshold is 3) |
| `ufw_multi_ip_scan.log` | Two independent scanning IPs — confirms per-IP counting |
| `nginx_clean.log` | No findings |
| `nginx_recon_heavy.log` | Multiple recon probes (`wp-admin`, `.env`, path traversal, `phpmyadmin`) |
| `nginx_single_probe_boundary.log` | Exactly one recon hit — confirms no threshold on this rule (unlike brute-force/port-scan) |
| `apache_clean.log` | No findings |
| `apache_recon_scanner.log` | Recon probes with an Nmap-style user agent, Apache Combined Log Format |

Real syntax basis: RFC 3164 syslog for auth.log/UFW (including UFW's real netfilter field order),
Combined Log Format for nginx/Apache. All IPs use RFC 5737 documentation ranges
(`192.0.2.x` / `198.51.100.x` / `203.0.113.x`) — none are real.

## `infra/` — 14 files (`trivy config`, via `agents/vuln_scanner.py`)

| File | Trivy check | Expected result |
|---|---|---|
| `Dockerfile.hardened` | — | Zero findings (verified) |
| `Dockerfile.vulnerable` | DS-0002, DS-0026 | Root user + missing HEALTHCHECK (verified) |
| `Dockerfile.multistage_edge_case` | DS-0026 only | **Verified real Trivy blind spot**: DS-0002 (root user) does NOT fire here even though the shipped final stage genuinely runs as root — Trivy's check appears satisfied by *any* stage in the file declaring `USER`, not specifically the final one. See the in-file comment; this is a deliberate "looks safe, isn't" case, not a fixture bug |
| `k8s_pod_hardened.yaml` | — | Zero findings (verified against Trivy's full ~18-check K8s ruleset, not just the targeted ones — required adding `runAsUser`/`runAsGroup`/`seccompProfile`/non-default namespace beyond the originally-planned fields) |
| `k8s_pod_privileged_hostnetwork.yaml` | KSV-0001, KSV-0009, KSV-0012, KSV-0014, KSV-0017, KSV-0118 (+ several LOW) | `privileged: true` + `hostNetwork: true` (verified, 18 findings) |
| `k8s_deployment_no_resource_limits.yaml` | KSV-0011/0015/0016/0018 (CPU/memory limits+requests) | No resource limits |
| `k8s_secrets_in_env.yaml` | — | Hardcoded secret in a plain env var (realistic anti-pattern; Trivy's config scanner doesn't have a dedicated "secret in env" check, so this fixture is more about human/manual review than a Trivy finding) |
| `k8s_deployment_hardened_full.yaml` | — | Zero findings (verified) |
| `helm_rendered_hardened.yaml` | — | Zero findings; **verified `Type: kubernetes` in Trivy's JSON output** (not `helm`), confirming the pre-render-and-upload path genuinely works |
| `helm_rendered_vulnerable.yaml` | Same as k8s_pod_privileged_hostnetwork-class | Verified `Type: kubernetes`, 17 findings |
| `terraform_hardened.tf` | — | 5 low/medium findings unrelated to the two targeted checks below (missing descriptions, no bucket logging/versioning, no customer-managed KMS key) — none of the security-group/public-access findings the vulnerable pair has |
| `terraform_vulnerable_open_sg_s3.tf` | AWS-0107 (open SSH/RDP ingress), AWS-0086/0087/0091/0093/0094 (S3 public-access-block family) | 11 findings — 6 more than the hardened pair, all on the targeted checks |
| `cloudformation_hardened.yaml` | — | Same shared low/medium findings as terraform_hardened, none of the targeted ones |
| `cloudformation_vulnerable_open_sg_s3.yaml` | Same check IDs as above | Same pattern, CloudFormation syntax |

Empirically verified via a real `trivy config` run (not just cited from docs): exact check IDs
confirmed above differ slightly from Trivy's own AVD documentation page numbering at the time of
initial research (`AVD-AWS-0088`/`AVD-AWS-0086`) — Trivy's internal IDs evidently shifted since;
what matters for the fixture pair is the **11 vs. 5 finding-count gap and the specific
public-access-block + open-ingress checks only firing on the vulnerable file**, both confirmed.

**Why there's no docker-compose or raw Helm chart fixture, and why Go dependencies use `go.mod`
not `go.sum`:** confirmed via current Trivy docs/GitHub state (dated citations in the session that
produced this fixture set) that:
- **`docker-compose.yml` is not scanned by `trivy config` at all** — no native parser exists
  (open feature request, no maintainer commitment). A compose fixture would produce zero findings
  regardless of content, which isn't a useful test. `FILE_HELP` in `ui_render.py` no longer lists
  it as supported.
- **Raw Helm charts need the full chart directory** (`Chart.yaml` + `values.yaml` + `templates/`)
  to be recognized — but this app's upload slots are single-file only, so a lone template can
  never exercise Trivy's Helm-specific path. Fixed by uploading the *output* of
  `helm template mychart > rendered.yaml` instead (`helm_rendered_*.yaml` above) — fully resolved
  plain Kubernetes YAML, scanned via the Kubernetes manifest path, not Helm parsing. This
  particular claim is inferred from how Trivy's two scanners are triggered (plain `apiVersion`/
  `kind` YAML vs. `Chart.yaml` presence) rather than an explicit doc statement — verify empirically
  (run `trivy config` on a dir with just `helm_rendered_hardened.yaml` and confirm the JSON
  result's `Type` is `kubernetes`) before treating the UI's "pre-render and upload" hint as settled.
- **Terraform/CloudFormation have real but partial support**: a single file can't resolve remote/
  provider state, and CloudFormation is documented to silently skip templates using some advanced
  intrinsic functions (`Fn::ForEach`, some `!Ref`/Condition patterns) rather than erroring — zero
  findings on those isn't necessarily a clean bill of health. The fixtures above deliberately use
  only simple resource properties to avoid tripping that gap.

## `dependencies/` — 16 files (`trivy fs --scanners vuln`, uploaded via the requirements slot)

| Ecosystem | Vulnerable pin(s) | CVE | Clean counterpart |
|---|---|---|---|
| Python (`requirements_vulnerable.txt`) | `pyyaml==5.1`, `django==2.0.1` | CVE-2020-14343, CVE-2018-6188/7537 | `requirements_clean.txt` |
| Python (`requirements_unpinned.txt`) | loose ranges (`flask>=2.0` etc.) | — (tests the app's own regex silently skipping unpinned deps) | — |
| Python (`requirements_mixed.txt`) | `pyyaml==5.1` alongside a patched `django` pin | CVE-2020-14343 | partial remediation case |
| Node (`package-lock_vulnerable.json`) | `lodash==4.17.15`, `minimist==1.2.5` | CVE-2020-8203, CVE-2020-7598 | `package-lock_clean.json` |
| Node (`yarn_vulnerable.lock`) | `lodash==4.17.15` | CVE-2020-8203 | `yarn_clean.lock` (dev/prod classification is degraded without a sibling `package.json`, which this single-file upload can't provide — not a functional blocker) |
| Go (`go_vulnerable.mod`) | `dgrijalva/jwt-go v3.2.0+incompatible`, `golang.org/x/text v0.3.0` | CVE-2020-26160, CVE-2022-32149 | `go_clean.mod` |
| Java (`pom_vulnerable.xml`) | `log4j-core:2.14.1` | CVE-2021-44228 (Log4Shell) | `pom_clean.xml` (Trivy may hit Maven Central rate limits resolving metadata on a cold cache — a documented flakiness source, not a fixture defect) |
| Ruby (`Gemfile_vulnerable.lock`) | `nokogiri (1.8.0)`, `rails (4.2.0)` | CVE-2018-14404, CVE-2019-5418 | `Gemfile_clean.lock` |
| Rust (`Cargo_vulnerable.lock`) | `time 0.1.42` | CVE-2020-26235 | `Cargo_clean.lock` |

**Go uses `go.mod`, not `go.sum`** — Trivy needs `go.mod` to determine the Go version/module
identity at all; a standalone `go.sum` does not reliably produce findings (documented on Trivy's
own Go coverage page). `FILE_HELP` reflects this.

## `policy/` — 7 files (`agents/policy_checker.py` RAG retrieval)

| File | Tests |
|---|---|
| `policy_custom_topic.md` | Non-NIST clauses win on a genuine non-overlapping match |
| `policy_overlapping_nist.md` | Competition against the built-in catalog on a near-duplicate topic |
| `policy_malformed_no_headings.md` | Chunker's `## `-based split finding nothing, without crashing |
| `policy_short_single_clause.md` | Smallest valid input |
| `policy_comprehensive_iso_soc2_style.md` | Denser, realistic multi-clause upload |
| `policy_empty_or_whitespace.md` | Near-empty file — extreme edge case |
| `policy_multi_match_conflict.md` | A clause close to more than one NIST control at once — ranking/tie-handling |
