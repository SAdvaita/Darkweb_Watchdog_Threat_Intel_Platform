# Playbook: Ransomware Victim

**MITRE ATT&CK**: T1486, T1195  
**NIST SP 800-61 Phase**: Detect → Contain → Eradicate → Recover

## Detect
- [ ] Confirm organization name on leak site (may be spelling variant)
- [ ] Check `data_origin` field (`live` vs `replay`)
- [ ] Cross-reference with internal incident records

## Contain
- [ ] Escalate to CISO immediately if confirmed
- [ ] Preserve evidence of the leak-site listing (screenshot + STIX export)
- [ ] Identify what data may have been exfiltrated
- [ ] Isolate any systems known to be compromised

## Eradicate
- [ ] Coordinate with legal counsel on notification obligations
- [ ] Contact law enforcement if appropriate
- [ ] Engage incident response retainer

## Recover
- [ ] Notify affected parties per regulatory requirements
- [ ] Update threat intelligence with the group's TTPs from ransomware.live
- [ ] Conduct post-incident review

**Owner**: CISO  
**Target**: Acknowledge within 1 hour (Critical), Contain within 4 hours
