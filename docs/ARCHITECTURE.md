# Mail Warden Architecture

## Intent

Mail Warden is a DMZ-resident SMTP security gateway for on-prem Exchange, focused on behavioral intelligence rather than basic spam scoring.

## Processing Pipeline

1. Connection analysis
   - IP, PTR/rDNS, ASN, protocol behavior, connection rate
2. Envelope analysis
   - MAIL FROM / RCPT TO validation and enumeration detection
3. Identity and relationship context
   - Sender/domain history, correspondent history, organizational context
4. Content analysis
   - Rspamd, SPF, DKIM, DMARC, URL and attachment results, malware integrations
5. Policy decision
   - Hard security gates
   - Bounded-trust score + risk model
6. Action
   - Accept, quarantine, reject, throttle, or temporary fail

## Service Boundaries

- Postfix: SMTP transport
- Rspamd: content/authentication analysis
- Mail Warden core (Go): normalization, scoring, policy, relationship/reputation logic
- PostgreSQL: durable intelligence and event ledger
- Redis: rate limiting/counters/transient reputation state
- ClamAV: malware engine

## Inbound/Outbound Symmetry

- Inbound traffic is inspected before relay to Exchange.
- Outbound traffic is inspected from Exchange smart-host path.
- Outbound activity seeds relationship intelligence and baseline behavior profiles.

## Security Principle: Bounded Trust

Positive relationship history can help classification, but cannot override hard evidence like malware confirmation or critical malicious URL findings.

## Degradation Strategy

- Full mode: all dependencies healthy
- Reduced mode: Rspamd unavailable -> connection/envelope/reputation only
- Safe mode: DB unavailable -> cached state + conservative policy
- Critical failure: controlled temporary reject

## Implemented Foundation (Current)

- HTTP policy API with inbound/outbound decision handling
- Explainable bounded-signal scoring output and hard security gates
- Postfix policy-delegation listener for SMTP-time envelope decisions
- Redis-backed outbound velocity/recipient diversity counters
- PostgreSQL migrations runner and quarantine persistence repository
- Background reputation-decay worker
- Local+LDAP auth, JWT sessions, and RBAC middleware
- Policy versioning/rollback and configuration snapshot storage
- Cluster heartbeat and stale-node tracking foundation
