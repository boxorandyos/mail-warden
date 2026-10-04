# Mail Warden Threat Model (Baseline)

## Protected Assets

- Internal Exchange availability and integrity
- Mailbox identities and relationship intelligence
- Sensitive email content and attachments
- Quarantine data and release workflow integrity

## Primary Threats

- Phishing and BEC
- Malware distribution
- Directory enumeration/harvesting via SMTP
- Compromised internal mailbox mass outbound abuse
- Spoofing and authentication bypass attempts

## Trust Boundaries

- Internet to DMZ SMTP boundary
- DMZ Mail Warden to internal Exchange boundary
- Management/API plane isolated from public ingress
- Identity provider boundaries (LDAP/Entra)

## Security Controls

- Hard security gates for high-confidence detections
- Bounded scoring with signal caps and saturation
- Least-privilege service accounts
- Strict firewall ACLs and interface exposure
- Structured audit trails for policy and release actions

## Data Minimization

- Retain metadata and event ledger longer-term
- Minimize retention of message body/attachments
- Configurable quarantine retention and purging
