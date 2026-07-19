## Monitoring and Authentication Combined Control
Failed SSH logon attempts must be monitored, reviewed for anomalous patterns, and reported to
designated personnel; accounts exhibiting repeated failed authentication must additionally be
temporarily locked and require strong, uniquely-attributable re-authentication before regaining
access. This clause deliberately straddles both an audit/monitoring control and an
authentication/lockout control at once, so a finding matching it can plausibly rank close to
more than one NIST control family (e.g. AU-6/SI-4 vs. AC-7/IA-2) - useful for confirming the
retrieval ranking and tie-handling doesn't crash or silently misbehave on ambiguous matches.
