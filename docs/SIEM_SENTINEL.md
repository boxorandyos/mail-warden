# SIEM / Sentinel Integration

Mail Warden supports webhook forwarding of high-value policy and audit events.

## Configuration

In `configs/mailwarden.example.yaml`:

```yaml
siem:
  enabled: true
  webhook_url: "https://siem.example.local/ingest/mailwarden"
  bearer_token: ""
  timeout_seconds: 5
```

Secrets can be injected via:

- `MAILWARDEN_SIEM_BEARER_TOKEN`
- `MAILWARDEN_SIEM_BEARER_TOKEN_FILE`
- Vault key: `siem_bearer_token`

## Event classes currently forwarded

- policy decision events (`policy_decision`)
- audit events:
  - policy version created
  - policy rollback
  - identity provider upsert/delete
  - quarantine release

## Sentinel mapping suggestion

Map webhook payloads into custom table `MailWarden_CL` with these fields:

- `Type_s`
- `Event_s`
- `ActorUserId_s`
- `MessageId_s`
- `Direction_s`
- `Action_s`
- `Score_d`
- `TimeGenerated`
