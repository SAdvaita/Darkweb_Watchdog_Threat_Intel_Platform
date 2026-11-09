# Playbook: Secret in Public Code

**MITRE ATT&CK**: T1552.001, T1593.003

## Detect
- [ ] Confirm the secret is genuine and not a placeholder value
- [ ] Determine which repository and commit exposed the secret
- [ ] Check commit history for how long it has been exposed

## Contain
- [ ] Immediately revoke the secret in the provider's console
- [ ] Remove the secret from repository history (`git filter-repo`)
- [ ] Contact GitHub/platform to remove cached copies

## Eradicate
- [ ] Audit all systems the secret provided access to
- [ ] Check access logs for unauthorized use during the exposure window
- [ ] Rotate all secrets in the same environment

## Recover
- [ ] Issue a new secret with minimal required permissions
- [ ] Add a pre-commit hook (`git-secrets` or `truffleHog`) to prevent future leaks
- [ ] Enroll in GitHub secret scanning push protection if not already done

**Owner**: DevSecOps  
**Target**: Acknowledge within 4 hours, Contain within 24 hours
