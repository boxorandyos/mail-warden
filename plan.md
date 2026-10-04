# Mail Warden

Open-Source Email Security Gateway for On-Premises Exchange

**Project Status:** Concept / Architecture Phase  
**Primary Target:** On-premises Microsoft Exchange  
**Deployment Model:** DMZ-based SMTP security gateway  
**Primary Inspiration:** Nginx Warden  
**Core Filtering Engine:** Rspamd  
**Identity Sources:** Exchange mail flow, Active Directory, Microsoft Entra ID  
**Traffic Direction:** Inbound and outbound  
**Design Philosophy:** Behavioral email security rather than simple spam filtering

---

## 1. Executive Summary

Mail Warden is proposed as an open-source email security gateway designed to sit in the DMZ between the Internet and an organization's internal Exchange infrastructure.

The project is conceptually analogous to Nginx Warden:

> Nginx Warden protects web servers by understanding HTTP traffic and client behavior.  
> Mail Warden protects mail infrastructure by understanding SMTP traffic, mail behavior, identity, reputation, and relationships.

Mail Warden should not simply be another SpamAssassin/ClamAV front end.

Its distinguishing feature should be multi-dimensional behavioral intelligence.

The system should evaluate:

- SMTP connections
- source IPs
- ASN/infrastructure
- HELO/EHLO behavior
- SMTP envelope information
- sender identities
- recipient validity
- SPF
- DKIM
- DMARC
- ARC
- message content
- URLs
- attachments
- malware
- sending velocity
- recipient patterns
- inbound/outbound relationships
- historical correspondence
- directory information
- reputation
- account-compromise indicators
- phishing/BEC behavior

The system should also monitor outbound email, not merely inbound mail.

This creates a feedback loop in which legitimate outbound traffic becomes useful intelligence for evaluating future inbound traffic.

---

## 2. Primary Design Goal

The primary goal is:

> Build an email security firewall that understands whether a mail interaction behaves like legitimate communication.

The system should answer questions at multiple levels.

**Connection**

> Is this SMTP client behaving normally?

**Infrastructure**

> Is this IP/domain/ASN associated with legitimate mail activity?

**Identity**

> Is this sender actually who they claim to be?

**Recipient**

> Does this recipient exist?

**Behavior**

> Is this sender behaving normally?

**Relationship**

> Does this sender normally communicate with this organization/user?

**Content**

> Is this message malicious, suspicious, or anomalous?

**Organizational context**

> Does this message make sense given what the organization normally does?

This is fundamentally different from:

> "Does this message have a spam score above X?"

---

## 3. High-Level Architecture

The proposed architecture is:

```
                              INTERNET
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                 SMTP 25                    HTTPS/API
                    │                           │
                    ▼                           ▼
          ┌───────────────────┐        ┌─────────────────┐
          │                   │        │ Nginx Warden   │
          │    MAIL WARDEN    │        │ / Management   │
          │                   │        │ Access         │
          │ SMTP Gateway      │        └────────┬────────┘
          │ Connection Engine │                 │
          │ Policy Engine     │                 │
          │ Reputation Engine │                 │
          │ Rspamd            │                 │
          │ Quarantine        │                 │
          │ Intelligence DB   │                 │
          └─────────┬─────────┘                 │
                    │                           │
                    │ SMTP                      │
                    ▼                           │
             ┌───────────────┐                  │
             │    EXCHANGE   │◄─────────────────┘
             │   ON-PREMISE  │
             └───────────────┘
                    │
                    │
              AD / Entra ID
                    │
                    ▼
             Identity Provider
```

Mail Warden itself is the SMTP gateway.

It does not require an Nginx reverse proxy in front of the SMTP path.

Nginx Warden may optionally protect the Mail Warden management interface/API, but SMTP should terminate at Mail Warden.

---

## 4. DMZ Placement

Mail Warden should reside in the existing DMZ alongside the organization's other security infrastructure.

Recommended network topology:

```
                         INTERNET
                             │
                         Firewall
                             │
                    ┌────────▼────────┐
                    │      DMZ        │
                    │                 │
                    │ Nginx Warden    │
                    │ Mail Warden     │
                    └────────┬────────┘
                             │
                         Firewall
                             │
                    ┌────────▼────────┐
                    │ INTERNAL NETWORK│
                    │                 │
                    │ Exchange        │
                    │ AD / DC         │
                    │ Entra services  │
                    └─────────────────┘
```

Firewall rules should explicitly restrict:

**Internet → Mail Warden**

Allow:

- TCP/25
- optionally TCP/465/587 only if there is a specific requirement

Do not expose administrative interfaces publicly.

**Mail Warden → Exchange**

Allow:

- SMTP to designated Exchange Receive Connector

**Mail Warden → AD**

Allow only the required directory protocol:

- LDAPS preferred
- tightly restricted destination/domain controllers
- read-only service account

**Mail Warden → Internet**

Allow only required services:

- DNS
- RBL/DNSBL lookups
- HTTPS threat-intelligence services
- outbound SMTP
- update repositories as appropriate

**Exchange → Mail Warden**

Allow outbound SMTP to the Mail Warden smart host.

Exchange supports Send Connectors configured to route outbound mail through a smart host, specifically including security appliances that scan outbound mail.

---

## 5. SMTP Is the Transport — Not the Entire Monitoring Model

SMTP is the protocol Mail Warden intercepts, but the system should monitor several layers.

### Layer 1 — Connection

Before message acceptance:

```
TCP connection
      ↓
Source IP
      ↓
PTR / DNS
      ↓
ASN
      ↓
HELO/EHLO
      ↓
TLS
      ↓
Connection rate
      ↓
Historical reputation
```

Potential signals:

- connection rate
- concurrent connections
- failed SMTP commands
- invalid HELO
- reverse DNS
- DNS reputation
- IP reputation
- ASN reputation
- geographic anomalies
- repeated connection failures
- connection bursts
- protocol violations

This is analogous to connection-level protection in Nginx Warden.

---

## 6. SMTP Envelope Monitoring

The next layer examines:

- MAIL FROM
- RCPT TO

before message content is accepted.

This provides valuable intelligence without requiring full message processing.

Examples:

- nonexistent recipients
- excessive recipient count
- recipient enumeration
- sender/recipient relationship
- sender velocity
- recipient diversity
- repeated failed recipients

This allows Mail Warden to identify directory-harvesting behavior.

Example:

```
attacker@example.net

aaa@company.com       INVALID
aab@company.com       INVALID
aac@company.com       INVALID
aaron@company.com     VALID
aaronb@company.com    INVALID
aaronc@company.com    INVALID
```

The important signal is not one invalid recipient.

The signal is:

> The sender appears to be probing the organization's address space.

---

## 7. Message Analysis

Once a message reaches the message-processing stage, Mail Warden should use Rspamd as the primary content-analysis engine.

Rspamd is well suited to this role because it is designed as an independent email-processing layer between an MTA and the Internet. It provides spam analysis, authentication checks, reputation mechanisms, Lua extensibility, and external-service integrations.

Its architecture is event-driven and multi-process, with dedicated normal, proxy, controller, and fuzzy-storage workers.

Relevant analysis includes:

- SPF
- DKIM
- DMARC
- ARC
- Bayesian analysis
- neural/statistical analysis
- fuzzy matching
- URL analysis
- reputation
- RBL/DNSBL
- MIME analysis
- attachment analysis
- antivirus integration
- custom rules

Rspamd's proxy worker supports Milter integration, load balancing, health checks, retransmission, and message mirroring, making it appropriate for integration with a Postfix-based SMTP layer.

Rspamd is Apache 2.0 licensed.

---

## 8. Recommended SMTP Foundation

Mail Warden should not reinvent SMTP.

The recommended architecture is:

```
Internet
   │
   ▼
Postfix / SMTP transport layer
   │
   ▼
Mail Warden policy service
   │
   ├── Rspamd
   ├── Reputation
   ├── Identity
   ├── Behavior
   └── Policy
   │
   ▼
Exchange
```

Postfix handles the mature, complicated SMTP transport implementation.

Mail Warden becomes the intelligence and policy layer.

Rspamd already integrates with MTAs through Milter and can operate in a proxy/self-scan architecture.

This dramatically reduces the amount of protocol code Mail Warden itself needs to own.

---

## 9. Inbound Mail Flow

Recommended inbound flow:

```
Internet
   │
   ▼
Firewall
   │
   ▼
Mail Warden
   │
   ├── Connection analysis
   │
   ├── IP reputation
   │
   ├── SMTP policy
   │
   ├── Envelope analysis
   │
   ├── Recipient validation
   │
   ├── Rspamd
   │
   ├── Malware analysis
   │
   ├── Reputation
   │
   └── Final policy
   │
   ├──── REJECT
   │
   ├──── QUARANTINE
   │
   └──── ACCEPT
           │
           ▼
       Exchange
```

Exchange Receive Connectors are explicitly designed to control inbound SMTP connections and can restrict the remote IP ranges that are allowed to connect.

Exchange should therefore accept Internet mail only from Mail Warden.

Direct Internet → Exchange SMTP should be eliminated.

---

## 10. Outbound Mail Flow

Outbound monitoring should be a first-class feature.

```
Exchange
   │
   ▼
Mail Warden
   │
   ├── Account compromise detection
   ├── Volume analysis
   ├── DLP
   ├── Malware
   ├── Reputation
   ├── Recipient analysis
   ├── Relationship learning
   └── Outbound policy
   │
   ▼
Internet
```

Exchange Send Connectors support smart-host routing, making this architecture directly compatible with Exchange. Microsoft specifically documents smart-host routing for sending outbound mail through appliances that scan outbound mail.

---

## 11. Outbound Mail as an Intelligence Source

One of the most important design decisions is that outbound traffic should not merely be inspected for DLP/spam.

It should also be used as organizational intelligence.

For example:

```
alice@company.com
       │
       ├────► bob@vendor.com
       ├────► jane@customer.com
       └────► support@partner.com
```

Mail Warden learns:

- which internal addresses are active
- which external addresses are used
- which external domains are legitimate
- which users communicate with which organizations
- frequency of communication
- historical relationships
- normal sending behavior

This means directory information can be learned from actual mail flow.

---

## 12. AD/Entra Is Still Valuable

Despite being able to learn from mail flow, Mail Warden should support directory integration.

The reason is that the two sources answer different questions.

**Mail flow**

> What actually exists and is being used?

**AD/Entra**

> What is supposed to exist?

**Exchange**

> What does the mail system consider valid?

The ideal system can combine all three.

```
                 ┌──────────────┐
                 │ Active       │
                 │ Directory    │
                 └──────┬───────┘
                        │
                 ┌──────▼───────┐
                 │              │
Exchange ───────►│ Mail Warden  │◄──── Entra ID
                 │              │
                 └──────┬───────┘
                        │
                  Intelligence
```

Entra ID can be queried through Microsoft Graph, with application permissions available for directory/user access. Permissions should be kept as narrow as practical because broader directory permissions require greater administrative authorization.

---

## 13. User Authentication and Quarantine

The realization that users will probably enable LDAP/Entra authentication is important.

The Mail Warden user portal should allow users to:

- view quarantined messages
- release messages
- report false positives
- report phishing
- manage personal allow/block preferences
- view message details appropriate to their permissions

Authentication options:

```
                Mail Warden
                     │
          ┌──────────┼──────────┐
          │          │          │
         LDAP       Entra     Local
          │          │       emergency
          │          │          │
          └──────────┼──────────┘
                     ▼
               User Portal
```

Local authentication should probably exist as a break-glass mechanism, but enterprise deployments should favor LDAP/Entra.

---

## 14. Reputation Model

The central innovation of Mail Warden should be a multi-dimensional reputation system.

Do not use one enormous score.

Instead:

```
                    MESSAGE
                       │
       ┌───────────────┼────────────────┐
       ▼               ▼                ▼
 Infrastructure     Identity        Relationship
       │               │                │
       └───────────────┼────────────────┘
                       ▼
                    Behavior
                       │
                       ▼
                    Content
                       │
                       ▼
                  Policy Engine
```

Suggested dimensions:

**Infrastructure**

- IP
- subnet
- ASN
- HELO
- reverse DNS
- infrastructure history

**Identity**

- sender address
- sender domain
- DKIM domain
- SPF
- DKIM
- DMARC
- ARC

**Relationship**

- known correspondent
- previous interactions
- direction of communication
- frequency
- last interaction
- relationship duration

**Behavior**

- recipient validity
- sending rate
- recipient diversity
- invalid-recipient ratio
- unusual volume
- unusual timing
- directory enumeration

**Content**

- spam
- phishing
- malware
- URL reputation
- attachment reputation
- suspicious language/content

---

## 15. Bounded Trust Model

A critical security requirement is:

> No individual trust source may overwhelm the other evidence.

For example, this is dangerous:

```
Known correspondent       +300
Good history               +1
SPF failure                -3
DKIM failure               -3
New infrastructure         -2
Malicious URL              -8
                         ----
                           285
```

A sender could become effectively immune to negative signals simply because of historical activity.

Instead:

```
Known correspondent       +300 → CAP +10
Good history               +1  → +1
SPF failure                -3  → -3
DKIM failure               -3  → -3
New infrastructure         -2  → -2
Malicious URL              -8  → -8
                                ----
                                  -5
```

This should be a foundational Mail Warden design principle.

---

## 16. Signal Caps

Every signal should have a bounded contribution.

Example:

| Signal | Range |
|--------|-------|
| Correspondent history | -10 .. +10 |
| Sender history | -10 .. +10 |
| Domain history | -10 .. +10 |
| IP reputation | -15 .. +15 |
| ASN reputation | -10 .. +10 |
| Infrastructure stability | -5 .. +5 |
| SPF | -10 .. +5 |
| DKIM | -10 .. +5 |
| DMARC | -15 .. +5 |
| Recipient behavior | -15 .. +5 |
| Sending velocity | -15 .. +5 |
| Recipient diversity | -10 .. +5 |
| Behavioral anomaly | -20 .. +5 |
| Spam | -20 .. +5 |
| Phishing | -30 .. +5 |
| Malware | -50 .. 0 |
| Malicious URL | -30 .. 0 |

The exact values should not be hard-coded initially.

They should be policy configuration.

---

## 17. Trust Should Saturate

Repeated evidence should have diminishing returns.

For example:

**Correspondence:**

```
1 interaction       +1
5 interactions      +4
10 interactions     +6
25 interactions     +8
50 interactions     +9
100+ interactions  +10
```

The 101st interaction does not create more trust.

Likewise:

**Invalid recipients:**

```
1%     -1
10%    -3
30%    -7
60%    -9
80%   -10
```

This prevents high-volume senders from accumulating enormous reputation.

---

## 18. Trust and Risk Should Be Separate Concepts

A further architectural refinement is to distinguish:

**Trust**

How much historical evidence supports the sender.

**Risk**

How dangerous the current event appears.

For example:

```
Trust:
    Correspondent history      +10
    Sender history              +5
    Domain history              +4

Risk:
    SPF failure                 HIGH
    DKIM failure                HIGH
    Malicious URL               CRITICAL
```

A trusted sender can still send a malicious message.

Therefore:

> Historical trust must never automatically override high-confidence current threats.

---

## 19. Hard Security Gates

Some detections should bypass normal scoring.

Examples:

- Confirmed malware
- Known malicious hash
- Known exploit
- High-confidence phishing
- Critical attachment detection
- Protocol abuse

Conceptually:

```
IF malware_confirmed
    → QUARANTINE/REJECT

ELSE IF malicious_url_high_confidence
    → QUARANTINE

ELSE
    → normal scoring
```

This prevents a heavily trusted correspondent from bypassing a confirmed malware detection.

---

## 20. Relationship Intelligence

One of the most powerful features should be the concept of a known correspondent.

Example:

```
alice@company.com
        │
        ▼
bob@vendor.com

Outbound: 87
Inbound: 74
First seen: 9 months ago
Last seen: 2 days ago
Authentication: consistent
Infrastructure: stable
```

This creates a relationship score.

An inbound message from "bob@vendor.com" may receive a modest positive signal.

But the relationship does not become an allowlist.

If the next message:

```
bob@vendor.com

SPF: FAIL
DKIM: FAIL
New IP
New ASN
Malicious URL
```

the relationship score cannot rescue it.

---

## 21. Business Email Compromise Detection

Relationship intelligence creates an opportunity for sophisticated BEC detection.

Example:

**Normal:**

```
accounting@company.com
        ↕
billing@vendor.com

300 messages
8 months
stable infrastructure
consistent DKIM
```

**Suddenly:**

```
billing@vendor.com
        │
        └── New infrastructure
        └── SPF failure
        └── DKIM failure
        └── unusual request
        └── new URL
```

Mail Warden should identify this as anomalous even if the sender address looks familiar.

This is substantially more valuable than conventional spam filtering.

---

## 22. Directory Enumeration Detection

The system should specifically detect recipient probing.

Example:

```
Attacker
   │
   ├── aaa@company.com      INVALID
   ├── aab@company.com      INVALID
   ├── admin@company.com    VALID
   ├── admin1@company.com   INVALID
   ├── admin2@company.com   INVALID
   └── accounting@company  VALID
```

Signals:

- high invalid-recipient percentage
- sequential usernames
- high recipient diversity
- large number of unique recipients
- high SMTP command rate

The system should be able to conclude:

> Likely directory harvesting / recipient enumeration

rather than merely:

> "Four recipients were invalid."

---

## 23. Account Compromise Detection

Outbound analysis enables detection of compromised Exchange accounts.

Example:

**Normal user:**

- 10–30 outbound messages/day
- 5 external domains

**Suddenly:**

- 4,000 messages
- 1,500 recipients
- 700 external domains

Mail Warden should identify:

> Possible compromised mailbox

Possible actions:

- throttle
- quarantine
- block outbound SMTP
- alert administrators
- notify security team
- optionally disable account through an integrated identity system in a future phase

The last action should require particularly careful authorization and should not be part of the initial MVP.

---

## 24. Outbound DLP

The outbound pipeline also creates an obvious place for DLP.

Potential future signals:

- sensitive file types
- large attachment volume
- unusual recipients
- mass external distribution
- regulated data patterns
- credentials/secrets
- financial information
- source code
- unusual data volume

DLP should initially be an optional module because false positives and privacy considerations are substantially different from spam filtering.

---

## 25. Quarantine Architecture

Quarantine should be a first-class subsystem.

```
                 Mail Warden
                     │
             ┌───────┴────────┐
             │                │
          Accepted        Quarantine
             │                │
             ▼                ▼
         Exchange        Quarantine DB
                              │
                              ▼
                        User Portal
```

Each quarantined message should retain:

- sender
- recipient
- timestamp
- source IP
- message ID
- reason
- score
- triggering rules
- authentication results
- relevant metadata
- original message where policy permits

Storage retention should be configurable.

---

## 26. Administrative Explainability

Every decision should be explainable.

Example:

```
Decision: QUARANTINE
Score: -18

Identity
  Known correspondent          +10

Infrastructure
  New sending IP                -5
  IP reputation                 -2

Authentication
  SPF failure                   -3
  DKIM failure                  -3

Content
  Malicious URL                 -10

Final score                    -13
```

The administrator should be able to answer:

> "Why did Mail Warden block this?"

without reading source code or digging through logs.

---

## 27. Event Model

Mail Warden should produce structured events.

Suggested event types:

- SMTP_CONNECTION
- SMTP_DISCONNECT
- SMTP_COMMAND
- SMTP_REJECT
- ENVELOPE_RECEIVED
- RECIPIENT_VALID
- RECIPIENT_INVALID
- MESSAGE_RECEIVED
- MESSAGE_SCANNED
- MESSAGE_ACCEPTED
- MESSAGE_REJECTED
- MESSAGE_QUARANTINED
- SPF_RESULT
- DKIM_RESULT
- DMARC_RESULT
- MALWARE_DETECTED
- PHISHING_DETECTED
- URL_DETECTED
- RATE_LIMIT
- DIRECTORY_ENUMERATION
- ACCOUNT_COMPROMISE_SUSPECTED
- RELATIONSHIP_CREATED
- RELATIONSHIP_UPDATED
- REPUTATION_CHANGED
- POLICY_DECISION

This makes observability much easier.

---

## 28. Data Model

A PostgreSQL-based system is appropriate for durable application data.

Redis can be used for:

- short-lived reputation state
- counters
- rate limiting
- caching
- Rspamd statistical data

Rspamd itself uses Redis for statistics/caching and rate limiting in common deployments.

A conceptual database model:

- organizations
- users
- domains
- mailboxes
- aliases
- ips
- asns
- infrastructure
- senders
- sender_domains
- external_contacts
- relationships
- messages
- message_events
- reputation_entities
- reputation_events
- policies
- policy_versions
- quarantine_messages
- authentication_results
- url_observations
- attachment_observations

---

## 29. Reputation Event Ledger

Rather than storing only a current score, retain the events that produced it.

Example:

```
IP 1.2.3.4

+2  successful historical delivery
+1  valid HELO
+1  SPF-associated domain
-3  invalid recipient burst
-5  spam campaign
-10 malicious URL campaign
```

The current reputation is derived from the event history.

Advantages:

- explainability
- debugging
- decay
- historical analysis
- machine-learning preparation
- easier policy changes
- ability to recalculate scores

---

## 30. Reputation Decay

Reputation should decay with time.

A sender that behaved badly two years ago should not necessarily remain permanently blocked.

Conceptually:

```
reputation(t) = previous_reputation × decay
              + new_events
```

Different signals should have different half-lives.

For example:

- **Malware event:** long memory
- **Spam campaign:** medium memory
- **Temporary rate spike:** short memory
- **Correspondence:** slowly decaying positive trust

---

## 31. Technology Stack

Recommended initial stack:

| Component | Recommendation |
|-----------|----------------|
| SMTP transport | Postfix |
| Message analysis | Rspamd |
| Antivirus | ClamAV initially |
| Cache/counters | Redis |
| Primary database | PostgreSQL |
| Core service | Go |
| Admin/API | Go |
| Web UI | React + TypeScript |
| Authentication | LDAP / Entra ID |
| Metrics | Prometheus |
| Logs | Structured JSON |
| Visualization | Built-in initially |
| Deployment | Linux VM/container |
| HA | Active/passive initially |

Rspamd is particularly attractive because it is Apache 2.0 licensed and exposes a Lua extension API, allowing custom rules without modifying the core engine.

---

## 32. Why Go for Mail Warden

Go is a strong candidate for the custom layer because Mail Warden needs:

- high concurrency
- networking
- SMTP integration
- HTTP APIs
- background workers
- LDAP
- database access
- Redis
- metrics
- structured logging
- low operational overhead

The performance requirements are not necessarily extreme initially, but Go makes it practical to build a compact, easily deployable appliance.

Rspamd remains responsible for high-performance message analysis.

---

## 33. Suggested Repository Structure

```
mail-warden/
│
├── cmd/
│   ├── mailwarden/
│   ├── policy-worker/
│   └── migrations/
│
├── internal/
│   ├── smtp/
│   ├── policy/
│   ├── reputation/
│   ├── identity/
│   ├── relationship/
│   ├── quarantine/
│   ├── rspamd/
│   ├── exchange/
│   ├── ldap/
│   ├── entra/
│   ├── database/
│   ├── events/
│   ├── scoring/
│   └── telemetry/
│
├── web/
│   ├── admin/
│   └── quarantine/
│
├── migrations/
│
├── configs/
│
├── deployments/
│   ├── docker/
│   ├── systemd/
│   └── vm/
│
├── docs/
│
└── tests/
```

---

## 34. Core Service Boundaries

The system should be modular.

```
SMTP
 │
 ▼
Connection Service
 │
 ▼
Envelope Service
 │
 ├── Identity Service
 │
 ├── Reputation Service
 │
 └── Relationship Service
 │
 ▼
Rspamd
 │
 ▼
Policy Engine
 │
 ├── Accept
 ├── Reject
 ├── Quarantine
 └── Throttle
```

The policy engine should not directly know how LDAP, Entra, Rspamd, or PostgreSQL works.

It should receive normalized facts.

---

## 35. Normalized Decision Object

A useful internal representation:

```json
{
  "connection": {
    "ip": "203.0.113.50",
    "asn": 64500,
    "rdns": "mail.example.net"
  },
  "envelope": {
    "from": "sender@example.net",
    "recipients": [
      "user@company.com"
    ]
  },
  "authentication": {
    "spf": "fail",
    "dkim": "fail",
    "dmarc": "fail"
  },
  "identity": {
    "sender_reputation": 2,
    "domain_reputation": 4
  },
  "relationship": {
    "known_correspondent": true,
    "score": 10
  },
  "behavior": {
    "recipient_validity": 0.82,
    "velocity": "high"
  },
  "content": {
    "rspamd_score": 8.7,
    "malicious_url": true
  },
  "decision": {
    "score": -12,
    "action": "quarantine"
  }
}
```

This provides a clean contract between analysis systems and the policy engine.

---

## 36. Policy Engine

Policies should be configurable.

Example:

```yaml
policy:
  inbound:
    reject:
      score: -30

    quarantine:
      score: -10

    accept:
      score: 0

    hard_blocks:
      - malware_confirmed
      - exploit_confirmed

reputation:
  correspondent:
    maximum_positive: 10

  ip:
    maximum_positive: 15
    maximum_negative: -15

  domain:
    maximum_positive: 10
    maximum_negative: -15
```

The exact policy should evolve through testing.

---

## 37. Do Not Make the Score the Only Decision

The policy engine should support:

**Score-based decisions**

- score <= -30 → reject
- score <= -10 → quarantine
- score > -10  → continue

**Rule-based decisions**

- malware_confirmed → quarantine

**Rate-based decisions**

- 5000 recipients/hour → throttle

**Relationship-based decisions**

- new sender + executive recipient + suspicious URL → quarantine

**Administrative policies**

- executive@company.com → stricter policy

---

## 38. Executive / High-Value Mailboxes

A future version should support per-user policy classes.

For example:

- NORMAL
- STRICT
- EXECUTIVE
- FINANCE
- HR
- ADMINISTRATOR

The same message could therefore produce different decisions depending on the recipient's risk profile.

This should be configurable rather than hard-coded.

---

## 39. Fail-Safe vs Fail-Open

This requires careful consideration.

If Rspamd becomes unavailable:

```
Internet → Mail Warden → Exchange
```

Mail Warden must decide whether to:

**Fail open**

Deliver mail without full filtering.

Pros:

- availability

Cons:

- security gap

**Fail closed**

Stop accepting mail.

Pros:

- security

Cons:

- mail disruption

**Recommended**

Use staged degradation:

```
Normal:
    full analysis

Rspamd unavailable:
    connection + envelope + reputation
    + basic policy

Database unavailable:
    cached reputation
    + safe baseline

Critical components unavailable:
    controlled temporary reject
```

The exact behavior should be configurable.

---

## 40. High Availability

Initial MVP can be single-node.

Production architecture should eventually support:

```
                 Internet
                    │
               Firewall/LB
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
    Mail Warden A       Mail Warden B
          │                   │
          └─────────┬─────────┘
                    ▼
             Shared state
          PostgreSQL / Redis
```

SMTP MX records can also provide multiple public endpoints.

Rspamd's architecture already supports forwarding/load balancing and health checks through its proxy worker.

---

## 41. Security Requirements

Mail Warden is security infrastructure, so its own attack surface must be treated as critical.

Requirements should include:

- minimal privileges
- separate service accounts
- no direct Internet access to admin interfaces
- TLS everywhere appropriate
- secure credential storage
- signed updates where practical
- structured audit logs
- rate limiting
- input validation
- sandboxed attachment processing
- process isolation
- minimal firewall rules
- regular security updates
- protected quarantine storage

The Rspamd controller/API should not be exposed directly to the Internet; its documentation recommends restricting production access to the controller worker.

---

## 42. Privacy Considerations

Mail Warden necessarily processes sensitive information.

The system may contain:

- email content
- attachments
- employee identities
- external contacts
- communication relationships
- potentially sensitive business information

Therefore the system should minimize retained content.

Recommended separation:

- **Metadata:** long-term
- **Reputation:** long-term
- **Message body:** short retention
- **Quarantine:** configurable retention
- **Attachments:** shortest practical retention

Administrators should be able to configure retention independently.

---

## 43. Logging

Logs should distinguish between:

**Operational logs**

- service started
- connection failed
- database unavailable
- Rspamd unavailable

**Security events**

- spam
- phishing
- malware
- enumeration
- rate limiting
- account compromise

**Audit events**

- administrator changed policy
- user released message
- administrator viewed quarantine
- configuration changed

Audit records should be tamper-resistant where practical.

---

## 44. Metrics

Recommended metrics:

- messages_received
- messages_accepted
- messages_rejected
- messages_quarantined
- smtp_connections
- smtp_rejections
- invalid_recipients
- rspamd_scan_latency
- rspamd_errors
- malware_detections
- phishing_detections
- spam_detections
- unique_senders
- unique_ips
- unique_domains
- outbound_messages
- outbound_recipients
- relationship_count
- reputation_changes
- quarantine_size

These metrics are useful for both operations and future machine learning.

---

## 45. MVP

The first version should not attempt to implement every idea above.

Recommended MVP:

**SMTP**

- Postfix
- inbound SMTP
- outbound SMTP
- Exchange integration

**Filtering**

- Rspamd
- SPF
- DKIM
- DMARC
- basic reputation
- ClamAV

**Intelligence**

- IP reputation
- sender reputation
- domain reputation
- recipient validity
- sending rate
- outbound relationship learning

**User portal**

- LDAP authentication
- quarantine
- release
- false-positive reporting

**Administration**

- policy configuration
- message tracking
- score explanation
- reputation view
- basic dashboards

**Observability**

- structured logs
- Prometheus metrics
- audit log

---

## 46. Phase 2

Add:

- Entra authentication
- Entra directory synchronization
- relationship graph
- recipient enumeration detection
- account compromise detection
- advanced rate limiting
- ASN reputation
- infrastructure reputation
- advanced URL analysis
- per-user policy

---

## 47. Phase 3

Add:

- BEC detection
- DLP
- attachment sandboxing
- threat-intelligence feeds
- campaign clustering
- fuzzy campaign detection
- machine-learning experimentation
- HA clustering
- multi-domain support

---

## 48. Phase 4

Potential advanced capabilities:

- automatic incident response
- integration with SIEM
- Microsoft Sentinel integration
- automatic account-risk notification
- automated threat intelligence sharing
- distributed reputation
- multi-organization reputation networks

These should come only after the core scoring system is demonstrably reliable.

---

## 49. What Mail Warden Should NOT Become

There are several traps to avoid.

- Don't build a new spam engine from scratch. **Use Rspamd.**
- Don't build a new SMTP implementation. **Use Postfix or another mature MTA.**
- Don't make AD mandatory. Mail-flow intelligence should work independently.
- Don't make Entra mandatory. It should be an integration.
- Don't make reputation equal allowlisting. A known sender can still be compromised.
- Don't make one score the security boundary. Hard security detections must be able to override reputation.
- Don't retain every email forever. Minimize data retention.
- Don't expose the administration interface to the Internet. Keep management separate.

---

## 50. Competitive Position

Proxmox Mail Gateway is an excellent reference point and demonstrates that a mail gateway can successfully operate between a firewall and an internal mail server, filtering both inbound and outbound traffic. It is open source under AGPLv3 and includes Postfix, ClamAV, SpamAssassin-based filtering, tracking, quarantine, and a web interface.

However, Mail Warden should deliberately differentiate itself.

**Traditional mail gateway**

- Spam score
- Virus
- RBL
- Quarantine

**Mail Warden**

```
Connection
    ↓
Infrastructure
    ↓
Identity
    ↓
Authentication
    ↓
Recipient intelligence
    ↓
Behavior
    ↓
Relationship
    ↓
Content
    ↓
Reputation
    ↓
Policy
```

The objective is not to replace Rspamd.

The objective is to build the intelligence and policy layer around it.

---

## 51. Core Differentiator

The strongest differentiator is:

> Mail Warden learns the organization's normal communication patterns from actual mail flow.

That allows it to understand:

- Who sends mail?
- Who receives mail?
- Who normally communicates with whom?
- What infrastructure do they use?
- How frequently?
- What does normal behavior look like?
- What changes when an account is compromised?

This creates an organization-specific security model.

---

## 52. Example Attack Detection

Consider a compromised external sender:

**Sender:** billing@trustedvendor.com

**Historical:**

- 200 legitimate messages
- 18 months of correspondence

**Current:**

- new IP
- SPF failure
- DKIM failure
- 2,000 recipients
- 70% invalid recipients
- malicious URL

A simplistic system might see:

Known sender → TRUSTED

Mail Warden should instead calculate:

```
Correspondent history       +10
Historical behavior          +5
New infrastructure           -5
SPF failure                  -3
DKIM failure                 -3
Recipient behavior           -8
Malicious URL               -10
──────────────────────────────
Final                        -14
```

Then:

**QUARANTINE**

The historical relationship helps establish that the sender is legitimate in general, while current evidence identifies that this specific event is dangerous.

That distinction is fundamental.

---

## 53. Example Internal Account Compromise

**Normal:**

```
alice@company.com

20 messages/day
10 external recipients
5 domains
```

**Compromised:**

```
alice@company.com

5,000 messages/hour
2,000 recipients
900 domains
large attachment volume
```

Mail Warden can detect the behavioral anomaly from outbound traffic even though Exchange itself considers the messages legitimate.

Potential result:

**ACCOUNT_COMPROMISE_SUSPECTED**

with:

- Outbound temporarily throttled
- Security alert generated
- Messages quarantined
- Administrator notified

Future versions could integrate with identity systems for automated response.

---

## 54. Product Philosophy

Mail Warden should be built around five principles.

1. **Evidence, not assumptions** — Every decision should be based on observable evidence.
2. **Bounded trust** — No single positive signal should overwhelm security evidence.
3. **Historical context** — Past behavior matters.
4. **Current behavior wins** — A trusted sender can become compromised.
5. **Explainability** — Administrators must understand every decision.

---

## 55. Final Recommended Architecture

The mature architecture should look approximately like this:

```
                           INTERNET
                               │
                               ▼
                         FIREWALL / ACL
                               │
                               ▼
                    ┌──────────────────────┐
                    │      MAIL WARDEN     │
                    │         DMZ          │
                    │                      │
                    │ SMTP / Postfix       │
                    │        │             │
                    │        ▼             │
                    │ Connection Engine    │
                    │        │             │
                    │        ▼             │
                    │ Envelope Engine      │
                    │        │             │
                    │   ┌────┴────┐        │
                    │   ▼         ▼        │
                    │ Identity  Reputation │
                    │   │         │        │
                    │   └────┬────┘        │
                    │        ▼             │
                    │      Rspamd          │
                    │        │             │
                    │        ▼             │
                    │   Behavior Engine    │
                    │        │             │
                    │        ▼             │
                    │ Relationship Engine  │
                    │        │             │
                    │        ▼             │
                    │    Policy Engine     │
                    │        │             │
                    │  ┌─────┼──────┐      │
                    │  ▼     ▼      ▼      │
                    │ ACCEPT QUAR. REJECT  │
                    │                      │
                    │ Intelligence DB      │
                    │ Redis / PostgreSQL   │
                    └──────────┬───────────┘
                               │
                         SMTP / TLS
                               │
                               ▼
                         ┌───────────┐
                         │ Exchange  │
                         └─────┬─────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
                   AD                  Entra ID
                    │                     │
                    └──────────┬──────────┘
                               │
                         Identity Data
```

---

## 56. Overall Assessment

This project is technically feasible and has a sensible path to an MVP because it does not require reinventing the fundamental components of email security.

The proposed division of responsibility is:

| Component | Role |
|-----------|------|
| Postfix | SMTP transport |
| Rspamd | message analysis |
| ClamAV | antivirus |
| Redis | fast transient state |
| PostgreSQL | durable intelligence |
| AD / Entra | authoritative identity context |
| Exchange | organizational mail system |
| Mail Warden | intelligence + reputation + behavioral analysis + policy + quarantine + user/admin experience |

That is the key architectural insight.

Mail Warden should not compete with Rspamd at filtering email.

It should make Rspamd substantially more powerful by providing context that a generic spam engine cannot know:

> Who are we? Who do we communicate with? What is normal for us? What is unusual? And what should we do about it?

That is what can make Mail Warden meaningfully different from another open-source mail gateway.
