# Internal Policy Excerpts (custom, non-NIST topics)

## Vendor Offboarding - Access Revocation
When a third-party vendor engagement ends, all vendor-issued accounts, API keys, VPN
credentials, and shared-drive access must be revoked within 24 hours of contract termination.
The offboarding ticket must record the revocation timestamp and the name of the engineer who
performed it.

## Physical Media Disposal
Decommissioned hard drives, SSDs, and backup tapes containing company data must be degaussed
or shredded by an approved vendor before disposal. A certificate of destruction must be
retained for 3 years.

## On-Call Escalation Runbook Ownership
Every production service must have a named on-call runbook owner, reviewed quarterly, with an
escalation path to a secondary on-call engineer if the primary does not acknowledge a page
within 15 minutes.
