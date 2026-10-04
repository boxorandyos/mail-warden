# Postfix production topology profile

This directory provides a hardened baseline for DMZ Mail Warden deployments.

## Files

- `main.cf` — queue behavior, relay, policy delegation, milter integration
- `master.cf` — SMTP/submission services and process definitions

## Validation checklist

1. `postconf -n` reflects expected relay/policy settings.
2. `postfix check` passes.
3. `postfix reload` with no errors.
4. Queue stress validation:
   - sustained inbound and outbound messages
   - queue growth and drain behavior observed
   - no stuck/deferred flood under expected failure modes

## Exchange integration

- `relayhost` targets Exchange receive connector.
- Exchange send connector routes outbound through Mail Warden smart host.
