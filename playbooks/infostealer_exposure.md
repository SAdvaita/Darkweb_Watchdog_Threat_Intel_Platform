# Playbook: Infostealer Exposure

**MITRE ATT&CK**: T1555.003, T1078

## Detect
- [ ] Review Hudson Rock report for affected employee count and domains
- [ ] Identify which credentials may have been captured by stealers
- [ ] Correlate with any recent phishing or malware incidents

## Contain
- [ ] Force password reset for all employees in the affected domain
- [ ] Revoke all active sessions in your IdP (Okta, Azure AD, etc.)
- [ ] Enable MFA organization-wide if not already enforced

## Eradicate
- [ ] Deploy EDR to identify and remove stealers from affected endpoints
- [ ] Audit identity providers for unauthorized sessions or OAuth grants
- [ ] Revoke suspicious OAuth tokens

## Recover
- [ ] Re-enroll affected users with new credentials
- [ ] Update endpoint security policies to block stealer TTPs
- [ ] Increase log retention for identity events

**Owner**: Security Operations  
**Target**: Acknowledge within 4 hours, Contain within 24 hours
