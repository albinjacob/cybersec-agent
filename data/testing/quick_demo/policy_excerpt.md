# Mini Policy Reference (excerpts for RAG demo)
# Sources paraphrased/condensed from NIST SP 800-53, ISO/IEC 27001:2022, and SOC 2 Trust Services Criteria for demo purposes.

## NIST SP 800-53 - AC-7: Unsuccessful Logon Attempts
The system shall enforce a limit of consecutive invalid logon attempts by a user during a defined time period. After the limit, the system shall automatically lock the account/node or delay the next logon prompt. Repeated failed SSH logons from a single source within a short window indicates a control gap here.

## NIST SP 800-53 - IA-2: Identification and Authentication
Organizational users (including privileged users) must be uniquely identified and authenticated. Direct root login over SSH, or password-based auth for privileged accounts, violates this control. Key-based auth with MFA is required for privileged access.

## NIST SP 800-53 - AU-6: Audit Review, Analysis, and Reporting
Organizations must review and analyze system audit records for indications of inappropriate or unusual activity on a defined frequency, and report findings to designated personnel.

## NIST SP 800-53 - SI-4: System Monitoring
The system must monitor for attacks, indicators of potential attacks, and unauthorized connections, including inbound/outbound traffic monitoring at external boundaries (e.g. repeated SYN scans to unusual ports).

## ISO/IEC 27001:2022 - A.8.9: Configuration Management
Configurations, including security configurations of hardware, software, and networks, shall be established, documented, implemented, monitored, and reviewed. Containers/images running as root, or with world-writable permissions (e.g. chmod 777), are a configuration management gap.

## ISO/IEC 27001:2022 - A.8.8: Management of Technical Vulnerabilities
Information about technical vulnerabilities of information systems in use shall be obtained in a timely fashion, the organization's exposure evaluated, and appropriate measures taken. Unpatched/outdated dependencies with known CVEs fall under this control.

## ISO/IEC 27001:2022 - A.8.16: Monitoring Activities
Networks, systems, and applications shall be monitored for anomalous behavior and appropriate actions taken to evaluate potential information security incidents. Path traversal attempts, probing for /wp-admin or /.env, and other reconnaissance patterns are indicators requiring review.

## SOC 2 - CC6.1: Logical Access Controls
The entity implements logical access security software, infrastructure, and architectures to protect information assets from security events, including restricting privileged access and requiring strong authentication for administrative functions.

## SOC 2 - CC7.2: System Monitoring for Security Events
The entity monitors system components for anomalies that are indicative of malicious acts, natural disasters, and errors, and evaluates whether they represent security incidents.
