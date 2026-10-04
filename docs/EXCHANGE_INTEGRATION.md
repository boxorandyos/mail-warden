# Exchange Integration Model

## Inbound

1. Internet SMTP arrives at Mail Warden in DMZ.
2. Mail Warden performs staged analysis and policy decisions.
3. Accepted messages are relayed to a restricted Exchange Receive Connector.
4. Exchange accepts internet mail only from Mail Warden source IPs.

## Outbound

1. Exchange Send Connector routes outbound through Mail Warden smart host.
2. Mail Warden applies outbound policy (malware, velocity, DLP-ready checks).
3. Mail Warden relays to Internet when allowed.

## Recipient Validation

- Prefer controlled recipient verification methods (directory sync or Exchange-aware validation cache) to avoid real-time dependency spikes.
- Track invalid recipient ratios and pattern anomalies for enumeration detection.

## Operational Notes

- Keep Exchange direct internet exposure disabled for SMTP.
- Maintain strict source-IP restrictions on receive connectors.
- Use TLS where available across hop boundaries.
