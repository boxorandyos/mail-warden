# Rspamd production profile

`local.d/` contains baseline hardening and Mail Warden integration settings.

## Validation

1. `rspamadm configtest` succeeds.
2. Proxy worker is reachable at `127.0.0.1:11332` for Postfix milter.
3. `checkv2` endpoint works for Mail Warden API integrations.
4. Message latency and reject/quarantine actions are verified under load.
