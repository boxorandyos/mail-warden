import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  vus: Number(__ENV.VUS || 20),
  duration: __ENV.DURATION || "2m",
  thresholds: {
    http_req_duration: ["p(95)<750"],
    http_req_failed: ["rate<0.01"],
  },
};

const BASE = __ENV.MAILWARDEN_BASE_URL || "http://localhost:8080";
const TOKEN = __ENV.MAILWARDEN_BEARER_TOKEN || "";

const payload = JSON.stringify({
  direction: "inbound",
  message: {
    connection: { ip: "203.0.113.10", asn: 64500, rdns: "mail.example.net" },
    envelope: { from: "sender@example.net", recipients: ["user@company.com"] },
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    identity: { sender_reputation: 2, domain_reputation: 2 },
    relationship: { known_correspondent: true, interaction_count: 30 },
    behavior: { sending_velocity_level: "normal", recipient_diversity: 0.1, enumeration_likely: false },
    content: { rspamd_score: 1.2, malicious_url: false, malware_confirmed: false },
  },
});

export default function () {
  const res = http.post(`${BASE}/api/v1/policy/evaluate`, payload, {
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${TOKEN}`,
    },
  });

  check(res, {
    "status is 200": (r) => r.status === 200,
    "has decision action": (r) => r.body.includes('"action"'),
  });
  sleep(0.1);
}
