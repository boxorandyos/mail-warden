# VM Deployment Notes

Mail Warden is intended for DMZ deployment between Internet SMTP and internal Exchange.

## Firewall Baseline

Internet -> Mail Warden:

- Allow TCP/25
- Optionally allow TCP/465 and TCP/587 only if required
- Deny direct admin/API access from Internet

Mail Warden -> Exchange:

- Allow SMTP to the designated Exchange Receive Connector

Exchange -> Mail Warden:

- Configure Send Connector smart-host to Mail Warden for outbound inspection

Mail Warden -> AD/Entra/Internet:

- LDAPS only to restricted domain controllers
- DNS and required threat-intel HTTPS egress only

## Hardening

- Dedicated service accounts
- Least privilege firewall ACLs
- TLS for management plane
- OS patching and signed package sources
