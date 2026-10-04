# Exchange connector hardening verification

Use this runbook in staging and production change windows.

## Inbound connector checks

1. Exchange Receive Connector allows SMTP only from Mail Warden DMZ IPs.
2. Direct Internet source IP ranges are not permitted.
3. TLS configuration aligns with organization policy.

## Outbound connector checks

1. Exchange Send Connector routes through Mail Warden smart host.
2. DNS direct-send is disabled for internet outbound path.
3. Retry behavior is acceptable during Mail Warden maintenance windows.

## Validation steps

1. Send synthetic inbound test from Internet simulator -> Mail Warden -> Exchange.
2. Send synthetic outbound test from Exchange -> Mail Warden -> Internet sink.
3. Confirm message tracking logs in Exchange and Mail Warden match.
4. Confirm policy decision and quarantine behavior are recorded.

## Failure handling

- If mail flow bypasses Mail Warden, rollback connector scope immediately.
- If connector restrictions break business flow, switch to documented emergency profile and incident process.
