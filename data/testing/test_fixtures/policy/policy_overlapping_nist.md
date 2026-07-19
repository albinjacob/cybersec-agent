# Internal Policy Excerpts (paraphrases NIST wording closely)

## Account Lockout After Repeated Failed Logins
Users who fail to authenticate correctly after several consecutive attempts within a short
window must have their account temporarily locked or the next login attempt delayed, to slow
down automated password-guessing attacks. Repeated failed SSH logons from a single source in a
short window is exactly this kind of control gap.

## Unique Identification for Privileged Accounts
Every privileged user must be uniquely identified and must authenticate using strong,
individually-attributable credentials - shared root logins or password-only authentication for
administrative accounts are not acceptable; key-based authentication with multi-factor
verification is required.
