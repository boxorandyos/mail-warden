# Attachment Sandbox Integration

Mail Warden can invoke an external sandbox service for suspicious attachments.

## Configuration

```yaml
sandbox:
  enabled: true
  endpoint: "https://sandbox.example.local/api/v1/analyze"
  api_key: ""
  timeout_seconds: 10
  min_suspicion_hit: 1
```

Secrets can be supplied via:

- `MAILWARDEN_SANDBOX_API_KEY`
- `MAILWARDEN_SANDBOX_API_KEY_FILE`
- Vault key `sandbox_api_key`

## Runtime behavior

1. Attachments are extracted from RFC822 payloads.
2. Suspicious attachment candidates are selected by extension/type heuristics.
3. Sandbox is invoked when candidate count >= `min_suspicion_hit`.
4. If sandbox returns `malicious=true`, message is forced into malware/high-risk path.
