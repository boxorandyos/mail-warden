# Mail Warden

**Open-source email security gateway for on-premises Microsoft Exchange**

Mail Warden is designed to sit in the DMZ between the Internet and an organization's Exchange infrastructure. It focuses on **behavioral email security**—understanding SMTP traffic, identity, reputation, and communication relationships—not on being another spam-score front end.

| | |
|---|---|
| **Project status** | Concept / architecture phase |
| **Primary target** | On-premises Microsoft Exchange |
| **Deployment model** | DMZ-based SMTP security gateway |
| **Primary inspiration** | Nginx Warden (conceptual analogy) |
| **Core filtering engine** | [Rspamd](https://rspamd.com/) |
| **Identity sources** | Exchange mail flow, Active Directory, Microsoft Entra ID |
| **Traffic direction** | Inbound and outbound |

## Philosophy

> Nginx Warden protects web servers by understanding HTTP traffic and client behavior.  
> Mail Warden protects mail infrastructure by understanding SMTP traffic, mail behavior, identity, reputation, and relationships.

The goal is to build an email security firewall that understands whether a mail interaction **behaves like legitimate communication** for *your* organization—using evidence from connection behavior, authentication, recipient intelligence, outbound relationship learning, and content analysis—with **bounded trust** and **explainable** policy decisions.

## Documentation

The full architecture, reputation model, mail flows, MVP scope, and phased roadmap are in **[plan.md](plan.md)**.

## Intended technology stack (initial)

| Component | Recommendation |
|-----------|----------------|
| SMTP transport | Postfix |
| Message analysis | Rspamd |
| Antivirus | ClamAV (initially) |
| Cache / counters | Redis |
| Primary database | PostgreSQL |
| Core services & API | Go |
| Web UI | React + TypeScript |
| Authentication | LDAP / Entra ID |
| Metrics | Prometheus |
| Deployment | Linux VM or container |

## Repository layout (planned)

```
mail-warden/
├── cmd/
├── internal/     # smtp, policy, reputation, identity, rspamd, quarantine, …
├── web/          # admin & quarantine portals
├── migrations/
├── configs/
├── deployments/
├── docs/
└── tests/
```

Implementation has not started; this repository currently holds the product and architecture plan.

## License

To be determined when code is added.
