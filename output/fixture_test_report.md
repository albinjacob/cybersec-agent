# Fixture Test Report

Mode: `development`  |  Total: 50  |  PASS: 39  FAIL: 0  INFO: 11

## `log/`

| File | Verdict | Detail |
|---|---|---|
| `auth_clean.log` | PASS | types=[] |
| `auth_multi_severity.log` | PASS | types=['privileged_password_login', 'insecure_permission_change', 'ssh_bruteforce', 'port_scan'] |
| `auth_boundary_2fails.log` | PASS | types=['insecure_permission_change'] |
| `auth_nonascii.log` | INFO | must parse without crashing |
| `ufw_clean.log` | PASS | types=[] |
| `ufw_portscan_multi.log` | PASS | types=['port_scan'] |
| `ufw_boundary_2ports.log` | PASS | types=[] |
| `ufw_multi_ip_scan.log` | PASS | types=['port_scan', 'port_scan'] |
| `nginx_clean.log` | PASS | types=[] |
| `nginx_recon_heavy.log` | PASS | types=['recon_probe', 'recon_probe', 'recon_probe', 'recon_probe'] |
| `nginx_single_probe_boundary.log` | PASS | types=['recon_probe'] |
| `apache_clean.log` | PASS | types=[] |
| `apache_recon_scanner.log` | PASS | types=['recon_probe', 'recon_probe', 'recon_probe'] |

## `infra/`

| File | Verdict | Detail |
|---|---|---|
| `Dockerfile.hardened` | PASS | 0 findings |
| `Dockerfile.vulnerable` | PASS | 3 findings: ['DS-0002', 'DS-0026', 'DS-0029'] |
| `Dockerfile.multistage_edge_case` | PASS | 1 findings: ['DS-0026'] |
| `k8s_pod_hardened.yaml` | PASS | 0 findings |
| `k8s_pod_privileged_hostnetwork.yaml` | PASS | 18 findings: ['KSV-0001', 'KSV-0003', 'KSV-0004', 'KSV-0009', 'KSV-0011', 'KSV-0012', 'KSV-0014', 'KSV-0015', 'KSV-0016', 'KSV-0017', 'KSV-0018', 'KSV-0020', 'KSV-0021', 'KSV-0030', 'KSV-0104', 'KSV-0106', 'KSV-0110', 'KSV-0118'] |
| `k8s_deployment_no_resource_limits.yaml` | PASS | 17 findings: ['KSV-0001', 'KSV-0003', 'KSV-0004', 'KSV-0011', 'KSV-0012', 'KSV-0014', 'KSV-0015', 'KSV-0016', 'KSV-0018', 'KSV-0020', 'KSV-0021', 'KSV-0030', 'KSV-0104', 'KSV-0106', 'KSV-0110', 'KSV-0118', 'KSV-0118'] |
| `k8s_secrets_in_env.yaml` | INFO | Trivy has no dedicated secret-in-env check; other findings on this minimal manifest are expected (actual: 17 findings) |
| `k8s_deployment_hardened_full.yaml` | PASS | 0 findings |
| `helm_rendered_hardened.yaml` | PASS | 0 findings |
| `helm_rendered_vulnerable.yaml` | PASS | 17 findings: ['KSV-0001', 'KSV-0003', 'KSV-0004', 'KSV-0011', 'KSV-0012', 'KSV-0014', 'KSV-0015', 'KSV-0016', 'KSV-0017', 'KSV-0018', 'KSV-0020', 'KSV-0021', 'KSV-0030', 'KSV-0104', 'KSV-0106', 'KSV-0110', 'KSV-0118'] |
| `terraform_hardened.tf` | INFO | expected: some low/medium findings unrelated to the targeted checks (actual: 5 findings) |
| `terraform_vulnerable_open_sg_s3.tf` | PASS | 11 findings: ['AWS-0086', 'AWS-0087', 'AWS-0089', 'AWS-0090', 'AWS-0091', 'AWS-0093', 'AWS-0094', 'AWS-0099', 'AWS-0107', 'AWS-0124', 'AWS-0132'] |
| `cloudformation_hardened.yaml` | INFO | expected: same shared low/medium findings as terraform_hardened (actual: 4 findings) |
| `cloudformation_vulnerable_open_sg_s3.yaml` | PASS | 10 findings: ['AWS-0086', 'AWS-0087', 'AWS-0089', 'AWS-0090', 'AWS-0091', 'AWS-0093', 'AWS-0094', 'AWS-0107', 'AWS-0124', 'AWS-0132'] |

## `dependencies/`

| File | Verdict | Detail |
|---|---|---|
| `requirements_clean.txt` | PASS | 30 findings: ['CVE-2025-64459', 'CVE-2024-53908', 'CVE-2025-57833', 'CVE-2025-59681', 'CVE-2025-64458', 'CVE-2026-1207', 'CVE-2026-1287', 'CVE-2026-25673', 'CVE-2026-33034', 'CVE-2026-3902', 'CVE-2024-45230', 'CVE-2024-45231', 'CVE-2024-53907', 'CVE-2024-56374', 'CVE-2025-13372', 'CVE-2025-26699', 'CVE-2025-32873', 'CVE-2025-48432', 'CVE-2025-64460', 'CVE-2026-1312', 'CVE-2026-33033', 'CVE-2025-13473', 'CVE-2025-14550', 'CVE-2025-59682', 'CVE-2026-1285', 'CVE-2026-25674', 'CVE-2026-4277', 'CVE-2026-4292', 'CVE-2024-47081', 'CVE-2026-25645'] |
| `requirements_vulnerable.txt` | PASS | 19 findings: ['CVE-2019-19844', 'CVE-2020-7471', 'CVE-2025-64459', 'CVE-2018-6188', 'CVE-2019-3498', 'CVE-2019-6975', 'CVE-2022-36359', 'CVE-2025-57833', 'CVE-2025-64458', 'CVE-2018-14574', 'CVE-2018-7536', 'CVE-2019-11358', 'CVE-2021-33203', 'CVE-2024-45231', 'CVE-2025-48432', 'CVE-2018-7537', 'CVE-2019-20477', 'CVE-2020-14343', 'CVE-2020-1747'] |
| `requirements_unpinned.txt` | PASS | dependency_names=[] |
| `requirements_mixed.txt` | PASS | 31 findings: ['CVE-2025-64459', 'CVE-2024-53908', 'CVE-2025-57833', 'CVE-2025-59681', 'CVE-2025-64458', 'CVE-2026-1207', 'CVE-2026-1287', 'CVE-2026-25673', 'CVE-2026-33034', 'CVE-2026-3902', 'CVE-2024-45230', 'CVE-2024-45231', 'CVE-2024-53907', 'CVE-2024-56374', 'CVE-2025-13372', 'CVE-2025-26699', 'CVE-2025-32873', 'CVE-2025-48432', 'CVE-2025-64460', 'CVE-2026-1312', 'CVE-2026-33033', 'CVE-2025-13473', 'CVE-2025-14550', 'CVE-2025-59682', 'CVE-2026-1285', 'CVE-2026-25674', 'CVE-2026-4277', 'CVE-2026-4292', 'CVE-2019-20477', 'CVE-2020-14343', 'CVE-2020-1747'] |
| `package-lock_clean.json` | PASS | 3 findings: ['CVE-2026-4800', 'CVE-2025-13465', 'CVE-2026-2950'] |
| `package-lock_vulnerable.json` | PASS | 8 findings: ['CVE-2020-8203', 'CVE-2021-23337', 'CVE-2026-4800', 'NSWG-ECO-516', 'CVE-2020-28500', 'CVE-2025-13465', 'CVE-2026-2950', 'CVE-2021-44906'] |
| `yarn_clean.lock` | PASS | 3 findings: ['CVE-2026-4800', 'CVE-2025-13465', 'CVE-2026-2950'] |
| `yarn_vulnerable.lock` | PASS | 7 findings: ['CVE-2020-8203', 'CVE-2021-23337', 'CVE-2026-4800', 'NSWG-ECO-516', 'CVE-2020-28500', 'CVE-2025-13465', 'CVE-2026-2950'] |
| `go_clean.mod` | PASS | 2 findings: ['CVE-2025-30204', 'CVE-2026-56852'] |
| `go_vulnerable.mod` | PASS | 5 findings: ['CVE-2020-26160', 'CVE-2020-14040', 'CVE-2021-38561', 'CVE-2022-32149', 'CVE-2026-56852'] |
| `pom_clean.xml` | PASS | 4 findings: ['CVE-2025-68161', 'CVE-2026-34477', 'CVE-2026-34478', 'CVE-2026-34480'] |
| `pom_vulnerable.xml` | PASS | 7 findings: ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105', 'CVE-2021-44832', 'CVE-2025-68161', 'CVE-2026-34477', 'CVE-2026-34480'] |
| `Gemfile_clean.lock` | PASS | 15 findings: ['GHSA-353f-x4gh-cqq8', 'GHSA-c4rq-3m3g-8wgx', 'GHSA-mrxw-mxhj-p664', 'GHSA-5prr-v3j2-97mh', 'GHSA-v2fc-qm4h-8hqv', 'GHSA-wx95-c6cv-8532', 'GHSA-5v8h-3h3q-446p', 'GHSA-5w6v-399v-w3cc', 'GHSA-8678-w3jw-xfc2', 'GHSA-9cv2-cfxc-v4v2', 'GHSA-p67v-3w7g-wjg7', 'GHSA-phwj-rprq-35pp', 'GHSA-wfpw-mmfh-qq69', 'GHSA-wjv4-x9w8-wm3h', 'GHSA-g9g8-vgvw-g3vf'] |
| `Gemfile_vulnerable.lock` | PASS | 50 findings: ['CVE-2019-11068', 'CVE-2019-5477', 'GHSA-353f-x4gh-cqq8', 'CVE-2017-15412', 'CVE-2017-16932', 'CVE-2017-9050', 'CVE-2018-14404', 'CVE-2018-25032', 'CVE-2019-13118', 'CVE-2019-18197', 'CVE-2019-5815', 'CVE-2020-7595', 'CVE-2021-30560', 'CVE-2021-3517', 'CVE-2021-3518', 'CVE-2021-41098', 'CVE-2022-24836', 'CVE-2022-24839', 'CVE-2022-29181', 'GHSA-7rrm-v45f-jp64', 'GHSA-c4rq-3m3g-8wgx', 'GHSA-cgx6-hpwq-fhv5', 'GHSA-fq42-c5rg-92c2', 'GHSA-gx8x-g87m-h5q6', 'GHSA-mrxw-mxhj-p664', 'GHSA-v6gp-9mmm-c6p5', 'CVE-2017-18258', 'CVE-2018-8048', 'CVE-2019-13117', 'CVE-2021-3537', 'CVE-2022-23437', 'GHSA-2qc6-mcvw-92cw', 'GHSA-5prr-v3j2-97mh', 'GHSA-pxvg-2qj5-37jq', 'GHSA-v2fc-qm4h-8hqv', 'GHSA-wx95-c6cv-8532', 'GHSA-xc9x-jj77-9p9j', 'GHSA-xxx9-3xcr-gjj3', 'CVE-2020-26247', 'GHSA-5v8h-3h3q-446p', 'GHSA-5w6v-399v-w3cc', 'GHSA-8678-w3jw-xfc2', 'GHSA-9cv2-cfxc-v4v2', 'GHSA-p67v-3w7g-wjg7', 'GHSA-phwj-rprq-35pp', 'GHSA-r95h-9x8f-r3f7', 'GHSA-vvfq-8hwr-qm4m', 'GHSA-wfpw-mmfh-qq69', 'GHSA-wjv4-x9w8-wm3h', 'GHSA-g9g8-vgvw-g3vf'] |
| `Cargo_clean.lock` | PASS | 1 findings: ['CVE-2026-25727'] |
| `Cargo_vulnerable.lock` | PASS | 1 findings: ['CVE-2020-26235'] |

## `policy/`

| File | Verdict | Detail |
|---|---|---|
| `policy_custom_topic.md` | INFO | 25 policy gap(s) mapped (manual read-through, no fixed expectation) |
| `policy_overlapping_nist.md` | INFO | 25 policy gap(s) mapped (manual read-through, no fixed expectation) |
| `policy_malformed_no_headings.md` | INFO | 25 policy gap(s) mapped (manual read-through, no fixed expectation) |
| `policy_short_single_clause.md` | INFO | 25 policy gap(s) mapped (manual read-through, no fixed expectation) |
| `policy_comprehensive_iso_soc2_style.md` | INFO | 25 policy gap(s) mapped (manual read-through, no fixed expectation) |
| `policy_empty_or_whitespace.md` | INFO | 25 policy gap(s) mapped (manual read-through, no fixed expectation) |
| `policy_multi_match_conflict.md` | INFO | 25 policy gap(s) mapped (manual read-through, no fixed expectation) |
