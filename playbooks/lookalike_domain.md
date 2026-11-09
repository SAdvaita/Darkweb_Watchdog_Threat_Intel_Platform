# Playbook: Lookalike Domain Detected

**MITRE ATT&CK**: T1583.001, T1566

## Detect
- [ ] Confirm the domain is a lookalike (typosquat, homoglyph, or close edit distance)
- [ ] Check RDAP registration age — recently registered domains are higher risk
- [ ] Determine if the domain resolves and what it serves
- [ ] Check if it is already on any blocklist

## Contain
- [ ] File a UDRP complaint if the domain is used for phishing
- [ ] Submit the domain to Google Safe Browsing and other blocklists
- [ ] Alert employees not to click links containing the lookalike domain
- [ ] Add to email gateway blocklist immediately

## Eradicate
- [ ] Work with registrar to suspend the domain if used maliciously
- [ ] Contact hosting provider to take down phishing page

## Recover
- [ ] Consider registering common typosquats of your own domain proactively
- [ ] Update phishing awareness training

**Owner**: Security Operations  
**Target**: Acknowledge within 24 hours, Contain within 72 hours
