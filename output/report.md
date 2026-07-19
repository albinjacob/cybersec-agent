# Cybersecurity AI Agent - Incident & Compliance Report
_Generated 2026-07-19 03:58 UTC_

## Executive Summary
**Overall risk: CRITICAL** — 38 issue(s) detected across logs and dependencies (6 critical, 13 high, 16 medium, 3 low).
Start with **section 4 (Incident Response — Action Plan)** for prioritized remediation, then **section 5 (Policy Checker)** for the affected compliance controls.
_Reasoning mode per agent: {'log_monitor': 'mock', 'threat_intel': 'mock', 'vuln_scanner': 'mock', 'incident_response': 'mock', 'policy_checker': 'mock'}_

---
## 1. Log Monitor Agent
Log Monitor Agent - detected activity summary:
- [MEDIUM] insecure_permission_change: User 'deploy' set world-writable permissions (chmod 777) on a web-accessible path

## 2. Threat Intelligence Agent
Threat Intelligence Agent - exposure summary:
- [CRITICAL] CVE-2017-18342: In PyYAML before 5.1, the yaml.load() API could execute arbitrary code if used with untrusted data. The load() function has been deprecated in version 5.1 and the 'UnsafeLoader' has been introduced for backward compatibility with the function.
- [CRITICAL] CVE-2019-20477: PyYAML 5.1 through 5.1.2 has insufficient restrictions on the load and load_all functions because of a class deserialization issue, e.g., Popen is a class in the subprocess module. NOTE: this issue exists because of an incomplete fix for CVE-2017-18342.
- [CRITICAL] CVE-2020-1747: A vulnerability was discovered in the PyYAML library in versions before 5.3.1, where it is susceptible to arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader. Applications that use the library to process untrusted input may be vulnerable to this flaw. An attacker could use this flaw to execute arbitrary code on the system by abusing the python/object/new constructor.
- [CRITICAL] CVE-2017-7481: Ansible before versions 2.3.1.0 and 2.4.0.0 fails to properly mark lookup-plugin results as unsafe. If an attacker could control the results of lookup() calls, they could inject Unicode strings to be parsed by the jinja2 templating system, resulting in code execution. By default, the jinja2 templating language is now marked as 'unsafe' and is not evaluated.
- [HIGH] CVE-1999-0168: The portmapper may act as a proxy and redirect service requests from an attacker, making the request appear to come from the local host, possibly bypassing authentication that would otherwise have taken place.  For example, NFS file systems could be mounted through the portmapper despite export restrictions.
- [HIGH] CVE-2007-0404: bin/compile-messages.py in Django 0.95 does not quote argument strings before invoking the msgfmt program through the os.system function, which allows attackers to execute arbitrary commands via shell metacharacters in a (1) .po or (2) .mo file.
- [MEDIUM] CVE-2008-3687: Heap-based buffer overflow in the flask_security_label function in Xen 3.3, when compiled with the XSM:FLASK module, allows unprivileged domain users (domU) to execute arbitrary code via the flask_op hypercall.
- [MEDIUM] CVE-2014-1891: Multiple integer overflows in the (1) FLASK_GETBOOL, (2) FLASK_SETBOOL, (3) FLASK_USER, and (4) FLASK_CONTEXT_TO_SID suboperations in the flask hypercall in Xen 4.3.x, 4.2.x, 4.1.x, 3.2.x, and earlier, when XSM is enabled, allow local users to cause a denial of service (processor fault) via unspecified vectors, a different vulnerability than CVE-2014-1892, CVE-2014-1893, and CVE-2014-1894.
- [MEDIUM] CVE-2014-1893: Multiple integer overflows in the (1) FLASK_GETBOOL and (2) FLASK_SETBOOL suboperations in the flask hypercall in Xen 4.1.x, 3.3.x, 3.2.x, and earlier, when XSM is enabled, allow local users to cause a denial of service (processor fault) via unspecified vectors, a different vulnerability than CVE-2014-1891, CVE-2014-1892, and CVE-2014-1894.
- [MEDIUM] CVE-1999-0107: Buffer overflow in Apache 1.2.5 and earlier allows a remote attacker to cause a denial of service with a large number of GET requests containing a large number of / characters.
- [MEDIUM] CVE-1999-0551: HP OpenMail can be misconfigured to allow users to run arbitrary commands using malicious print requests.
- [MEDIUM] CVE-2014-0012: FileSystemBytecodeCache in Jinja2 2.7.2 does not properly create temporary directories, which allows local users to gain privileges by pre-creating a temporary directory with a user's uid.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-1402.
- [MEDIUM] CVE-2014-1402: The default configuration for bccache.FileSystemBytecodeCache in Jinja2 before 2.7.2 does not properly create temporary files, which allows local users to gain privileges via a crafted .cache file with a name starting with __jinja2_ in /tmp.
- [MEDIUM] CVE-2007-0405: The LazyUser class in the AuthenticationMiddleware for Django 0.95 does not properly cache the user name across requests, which allows remote authenticated users to gain the privileges of a different user.
- [LOW] CVE-2007-5712: The internationalization (i18n) framework in Django 0.91, 0.95, 0.95.1, and 0.96, and as used in other products such as PyLucid, when the USE_I18N option and the i18n component are enabled, allows remote attackers to cause a denial of service (memory consumption) via many HTTP requests with large Accept-Language headers.

## 3. Vulnerability Scanner Agent
Vulnerability Scanner Agent - scan results:
- [CRITICAL] CVE-2019-19844: django==2.0.1: Django: crafted email address allows account takeover
- [CRITICAL] CVE-2020-7471: django==2.0.1: django: potential SQL injection via StringAgg(delimiter)
- [CRITICAL] CVE-2025-64459: django==2.0.1: django: Django SQL injection
- [CRITICAL] CVE-2019-20477: pyyaml==5.1: PyYAML: command execution through python/object/apply constructor in FullLoader
- [CRITICAL] CVE-2020-14343: pyyaml==5.1: PyYAML: incomplete fix for CVE-2020-1747
- [CRITICAL] CVE-2020-1747: pyyaml==5.1: PyYAML: arbitrary command execution through python/object/new when FullLoader is used
- [HIGH] DS-0002: Image user should not be 'root': Specify at least 1 USER command in Dockerfile with non-root user as argument
- [HIGH] DS-0029: 'apt-get' missing '--no-install-recommends': '--no-install-recommends' flag is missed: 'apt-get update && apt-get install -y curl'
- [HIGH] CVE-2018-6188: django==2.0.1: django: Information leakage in AuthenticationForm
- [HIGH] CVE-2019-3498: django==2.0.1: python-django: Content spoofing via URL path in default 404 page
- [HIGH] CVE-2019-6975: django==2.0.1: python-django: memory exhaustion in django.utils.numberformat.format()
- [HIGH] CVE-2022-36359: django==2.0.1: An issue was discovered in the HTTP FileResponse class in Django 3.2 b ...
- [HIGH] CVE-2025-57833: django==2.0.1: django: Django SQL injection in FilteredRelation column aliases
- [HIGH] CVE-2025-64458: django==2.0.1: Django: Denial-of-service vulnerability in Django on Windows
- [HIGH] CVE-2018-1000656: flask==0.12.2: python-flask: Denial of Service via crafted JSON file
- [HIGH] CVE-2019-1010083: flask==0.12.2: python-flask: unexpected memory usage can lead to denial of service via crafted encoded JSON data
- [HIGH] CVE-2023-30861: flask==0.12.2: flask: Possible disclosure of permanent session cookie due to missing Vary: Cookie header
- [HIGH] CVE-2019-10906: jinja2==2.10: python-jinja2: str.format_map allows sandbox escape
- [HIGH] CVE-2018-18074: requests==2.6.0: python-requests: Redirect from HTTPS to HTTP does not remove Authorization header
- [MEDIUM] CVE-2018-14574: django==2.0.1: django: Open redirect possibility in CommonMiddleware
- [MEDIUM] CVE-2018-7536: django==2.0.1: django: Catastrophic backtracking in regular expressions via 'urlize' and 'urlizetrunc'
- [MEDIUM] CVE-2019-11358: django==2.0.1: jquery: Prototype pollution in object's prototype leading to denial of service, remote code execution, or property injection
- [MEDIUM] CVE-2021-33203: django==2.0.1: django: Potential directory traversal via ``admindocs``
- [MEDIUM] CVE-2024-45231: django==2.0.1: python-django: Potential user email enumeration via response status on password reset
- [MEDIUM] CVE-2025-48432: django==2.0.1: django: Django Path Injection Vulnerability
- [MEDIUM] CVE-2020-28493: jinja2==2.10: python-jinja2: ReDoS vulnerability in the urlize filter
- [MEDIUM] CVE-2024-22195: jinja2==2.10: jinja2: HTML attribute injection when passing user input as keys to xmlattr filter
- [MEDIUM] CVE-2024-34064: jinja2==2.10: jinja2: accepts keys containing non-attribute characters
- [MEDIUM] CVE-2024-56326: jinja2==2.10: jinja2: Jinja has a sandbox breakout through indirect reference to format method
- [MEDIUM] CVE-2025-27516: jinja2==2.10: jinja2: Jinja sandbox breakout through attr filter selecting format method
- [MEDIUM] CVE-2023-32681: requests==2.6.0: python-requests: Unintended leak of Proxy-Authorization header
- [MEDIUM] CVE-2024-35195: requests==2.6.0: requests: subsequent requests to the same host ignore cert verification
- [MEDIUM] CVE-2024-47081: requests==2.6.0: requests: Requests vulnerable to .netrc credentials leak via malicious URLs
- [MEDIUM] CVE-2026-25645: requests==2.6.0: requests: Requests: Security bypass due to predictable temporary file creation
- [LOW] DS-0026: No HEALTHCHECK defined: Add HEALTHCHECK instruction in your Dockerfile
- [LOW] CVE-2018-7537: django==2.0.1: django: Catastrophic backtracking in regular expressions via 'truncatechars_html' and 'truncatewords_html'
- [LOW] CVE-2026-27205: flask==0.12.2: flask: Flask: Information disclosure via improper caching of session data

## 4. Incident Response Agent - Action Plan
Incident Response Agent - prioritized action plan:

1. [CRITICAL] django==2.0.1: Django: crafted email address allows account takeover  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

2. [CRITICAL] django==2.0.1: django: potential SQL injection via StringAgg(delimiter)  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

3. [CRITICAL] django==2.0.1: django: Django SQL injection  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

4. [CRITICAL] pyyaml==5.1: PyYAML: command execution through python/object/apply constructor in FullLoader  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

5. [CRITICAL] pyyaml==5.1: PyYAML: incomplete fix for CVE-2020-1747  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

6. [CRITICAL] pyyaml==5.1: PyYAML: arbitrary command execution through python/object/new when FullLoader is used  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

7. [HIGH] Image user should not be 'root': Specify at least 1 USER command in Dockerfile with non-root user as argument  (from vuln_scanner)
   - Investigate and remediate per standard IR procedure.

8. [HIGH] 'apt-get' missing '--no-install-recommends': '--no-install-recommends' flag is missed: 'apt-get update && apt-get install -y curl'  (from vuln_scanner)
   - Investigate and remediate per standard IR procedure.

9. [HIGH] django==2.0.1: django: Information leakage in AuthenticationForm  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

10. [HIGH] django==2.0.1: python-django: Content spoofing via URL path in default 404 page  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

11. [HIGH] django==2.0.1: python-django: memory exhaustion in django.utils.numberformat.format()  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

12. [HIGH] django==2.0.1: An issue was discovered in the HTTP FileResponse class in Django 3.2 b ...  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

13. [HIGH] django==2.0.1: django: Django SQL injection in FilteredRelation column aliases  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

14. [HIGH] django==2.0.1: Django: Denial-of-service vulnerability in Django on Windows  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

15. [HIGH] flask==0.12.2: python-flask: Denial of Service via crafted JSON file  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

16. [HIGH] flask==0.12.2: python-flask: unexpected memory usage can lead to denial of service via crafted encoded JSON data  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

17. [HIGH] flask==0.12.2: flask: Possible disclosure of permanent session cookie due to missing Vary: Cookie header  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

18. [HIGH] jinja2==2.10: python-jinja2: str.format_map allows sandbox escape  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

19. [HIGH] requests==2.6.0: python-requests: Redirect from HTTPS to HTTP does not remove Authorization header  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

20. [MEDIUM] User 'deploy' set world-writable permissions (chmod 777) on a web-accessible path  (from log_monitor)
   - Revert world-writable permissions; set least-privilege ownership on the affected path.
   - Audit for any files dropped/modified while permissions were open.
   - Add a config-drift monitor/alert for permission changes on sensitive paths.

21. [MEDIUM] django==2.0.1: django: Open redirect possibility in CommonMiddleware  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

22. [MEDIUM] django==2.0.1: django: Catastrophic backtracking in regular expressions via 'urlize' and 'urlizetrunc'  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

23. [MEDIUM] django==2.0.1: jquery: Prototype pollution in object's prototype leading to denial of service, remote code execution, or property injection  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

24. [MEDIUM] django==2.0.1: django: Potential directory traversal via ``admindocs``  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

25. [MEDIUM] django==2.0.1: python-django: Potential user email enumeration via response status on password reset  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

26. [MEDIUM] django==2.0.1: django: Django Path Injection Vulnerability  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

27. [MEDIUM] jinja2==2.10: python-jinja2: ReDoS vulnerability in the urlize filter  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

28. [MEDIUM] jinja2==2.10: jinja2: HTML attribute injection when passing user input as keys to xmlattr filter  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

29. [MEDIUM] jinja2==2.10: jinja2: accepts keys containing non-attribute characters  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

30. [MEDIUM] jinja2==2.10: jinja2: Jinja has a sandbox breakout through indirect reference to format method  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

31. [MEDIUM] jinja2==2.10: jinja2: Jinja sandbox breakout through attr filter selecting format method  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

32. [MEDIUM] requests==2.6.0: python-requests: Unintended leak of Proxy-Authorization header  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

33. [MEDIUM] requests==2.6.0: requests: subsequent requests to the same host ignore cert verification  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

34. [MEDIUM] requests==2.6.0: requests: Requests vulnerable to .netrc credentials leak via malicious URLs  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

35. [MEDIUM] requests==2.6.0: requests: Requests: Security bypass due to predictable temporary file creation  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

36. [LOW] No HEALTHCHECK defined: Add HEALTHCHECK instruction in your Dockerfile  (from vuln_scanner)
   - Investigate and remediate per standard IR procedure.

37. [LOW] django==2.0.1: django: Catastrophic backtracking in regular expressions via 'truncatechars_html' and 'truncatewords_html'  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

38. [LOW] flask==0.12.2: flask: Flask: Information disclosure via improper caching of session data  (from vuln_scanner)
   - Upgrade the flagged package to the patched version referenced in the CVE.
   - Re-run the vulnerability scan post-upgrade to confirm remediation.
   - Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.

## 5. Policy Checker Agent - Compliance Gaps
Policy Checker Agent - compliance gaps:
- Finding: User 'deploy' set world-writable permissions (chmod 777) on a web-accessible path
  -> Maps to: ISO/IEC 27001:2022 - A.8.9: Configuration Management (similarity 0.39)
- Finding: Image user should not be 'root': Specify at least 1 USER command in Dockerfile with non-root user as argument
  -> Maps to: ISO/IEC 27001:2022 - A.8.9: Configuration Management (similarity 0.41)
- Finding: No HEALTHCHECK defined: Add HEALTHCHECK instruction in your Dockerfile
  -> Maps to: ISO/IEC 27001:2022 - A.8.9: Configuration Management (similarity 0.28)
- Finding: django==2.0.1: Django: crafted email address allows account takeover
  -> Maps to: NIST SP 800-53 - AC-2.4: Automated Audit Actions (similarity 0.31)
- Finding: django==2.0.1: django: Django SQL injection
  -> Maps to: NIST SP 800-53 - SI-10.6: Injection Prevention (similarity 0.26)
- Finding: django==2.0.1: django: Information leakage in AuthenticationForm
  -> Maps to: NIST SP 800-53 - IA-6: Authentication Feedback (similarity 0.36)
- Finding: django==2.0.1: Django: Denial-of-service vulnerability in Django on Windows
  -> Maps to: NIST SP 800-53 - SI-3: Malicious Code Protection (similarity 0.29)
- Finding: django==2.0.1: jquery: Prototype pollution in object's prototype leading to denial of service, remote code execution, or property injection
  -> Maps to: NIST SP 800-53 - SC-18.5: Allow Execution Only in Confined Environments (similarity 0.29)
- Finding: django==2.0.1: python-django: Potential user email enumeration via response status on password reset
  -> Maps to: NIST SP 800-53 - IA-5.1: Password-based Authentication (similarity 0.33)
- Finding: django==2.0.1: django: Django Path Injection Vulnerability
  -> Maps to: ISO/IEC 27001:2022 - A.8.8: Management of Technical Vulnerabilities (similarity 0.25)
- Finding: flask==0.12.2: flask: Possible disclosure of permanent session cookie due to missing Vary: Cookie header
  -> Maps to: NIST SP 800-53 - SC-23.1: Invalidate Session Identifiers at Logout (similarity 0.27)
- Finding: flask==0.12.2: flask: Flask: Information disclosure via improper caching of session data
  -> Maps to: NIST SP 800-53 - PM-21: Accounting of Disclosures (similarity 0.32)
- Finding: jinja2==2.10: python-jinja2: ReDoS vulnerability in the urlize filter
  -> Maps to: NIST SP 800-53 - AC-4.8: Security and Privacy Policy Filters (similarity 0.26)
- Finding: pyyaml==5.1: PyYAML: incomplete fix for CVE-2020-1747
  -> Maps to: NIST SP 800-53 - SI-10.2: Review and Resolve Errors (similarity 0.30)
- Finding: pyyaml==5.1: PyYAML: arbitrary command execution through python/object/new when FullLoader is used
  -> Maps to: NIST SP 800-53 - MP-8.1: Documentation of Process (similarity 0.26)
- Finding: requests==2.6.0: python-requests: Unintended leak of Proxy-Authorization header
  -> Maps to: NIST SP 800-53 - SC-7.8: Route Traffic to Authenticated Proxy Servers (similarity 0.36)
- Finding: requests==2.6.0: requests: subsequent requests to the same host ignore cert verification
  -> Maps to: NIST SP 800-53 - SC-17: Public Key Infrastructure Certificates (similarity 0.41)
- Finding: requests==2.6.0: requests: Requests vulnerable to .netrc credentials leak via malicious URLs
  -> Maps to: NIST SP 800-53 - SC-11: Trusted Path (similarity 0.32)
- Finding: requests==2.6.0: requests: Requests: Security bypass due to predictable temporary file creation
  -> Maps to: NIST SP 800-53 - SC-18.3: Prevent Downloading and Execution (similarity 0.41)

---
_This report was produced by a 5-agent pipeline (Log Monitor -> Vulnerability Scanner -> Threat Intelligence -> Incident Response -> Policy Checker) plus a terminal Notify action stage, orchestrated as a LangGraph directed graph. See README.md for which integrations ran live vs. fell back._