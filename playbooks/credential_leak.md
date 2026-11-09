# Playbook: Credential Leak

**MITRE ATT&CK**: T1589.001, T1078  
**NIST SP 800-61 Phase**: Detect → Contain → Eradicate → Recover

## Detect
- [ ] Confirm the finding is genuine (not a documentation sample or test fixture)
- [ ] Identify the source URL and when the credential was first published
- [ ] Determine which employee or service account is affected

## Contain
- [ ] Immediately revoke or rotate the exposed credential
- [ ] Force a password reset for the affected account(s)
- [ ] Enable MFA if not already enabled
- [ ] Block the credential from being reused via your IdP

## Eradicate
- [ ] Remove the credential from the public location if possible (contact platform)
- [ ] Search for other places the same credential may have been reused
- [ ] Audit access logs for suspicious activity during the exposure window

## Recover
- [ ] Issue new credentials with appropriate access scope
- [ ] Notify affected users per DPDP Act / GDPR obligations
- [ ] Update credential hygiene policies
- [ ] Add this credential pattern to monitoring rules

**Owner**: Security Operations  
**Target**: Acknowledge within 4 hours, Contain within 24 hours
