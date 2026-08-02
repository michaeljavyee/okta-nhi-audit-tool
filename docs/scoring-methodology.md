# Scoring methodology

How this tool decides that something is critical rather than medium, and why the
severity in the report means something specific rather than being a vibe.

---

## Severity definitions

Severity answers one question: **how soon must someone act, and what happens if
they don't?**

| Severity | Definition | Timeframe |
|---|---|---|
| **Critical** | Exploitable now, with org-wide blast radius. A credential that grants administrative control and is not tied to an accountable human. | 24 hours |
| **High** | Meaningful privilege held by an identity with weak or absent controls, or a credential whose owner cannot be established. | 30 days |
| **Medium** | A control gap or over-provisioning that does not by itself grant escalation, but widens the blast radius if the identity is compromised. | This quarter |
| **Low** | Hygiene and operational risk: unused credentials, missing ownership metadata, configuration that will cause an outage rather than a breach. | Backlog |

Two deliberate consequences of these definitions:

**Nothing is critical because it is embarrassing.** Critical requires both
administrative reach and absent ownership. An over-scoped OAuth app is high, not
critical, because someone provisioned it deliberately and it can be traced.

**Low is not "ignore this".** Several low findings — an idle token about to
expire, a correctly-configured SCIM connection — appear because the inventory is
the point. A client who has never seen a list of their machine identities gets
value from the entry existing, independent of anything being wrong with it.

---

## The two axes

Every severity assignment is a function of the same two questions.

### 1. Blast radius — what can this identity do?

| Reach | Examples |
|---|---|
| Tenant control | `SUPER_ADMIN`, `ORG_ADMIN`, `okta.users.manage`, `okta.roles.manage`, `okta.policies.manage` |
| Broad read/write | `APP_ADMIN`, `USER_ADMIN`, `okta.groups.manage`, SCIM write to a downstream system |
| Narrow | Read-only scopes, single-app assignment, `READ_ONLY_ADMIN` |
| None | No admin role, no scopes granted |

### 2. Control gap — what stops it being misused?

| Gap | Meaning |
|---|---|
| No accountable owner | Creator deprovisioned, or no owning team recorded anywhere |
| No second factor | Password or bearer token is the entire control |
| No expiry in practice | Static credential that never rotates |
| Unencrypted transport | Credential or data crosses the network in plaintext |
| No monitoring | Nothing would look wrong if the credential were used maliciously |

**The combination is what escalates.** High privilege with good controls is
manageable. Low privilege with poor controls is a hygiene item. High privilege
*and* absent controls *and* no owner is where critical lives.

---

## Applied: why the orphaned token is critical

Take the flagship finding — an API token created by a user who has since been
deprovisioned.

| Axis | Assessment |
|---|---|
| Blast radius | The token holds the admin privileges its creator had at creation. If they were a Super Admin, so is it. |
| Owner | None. The person is gone. Nobody knows what uses it. |
| Second factor | None. A bearer token is the whole credential. |
| Expiry | The 30-day clock resets on every use, so an automated job keeps it alive indefinitely. |
| Monitoring | Its activity looks like normal integration traffic. |

Every axis is at its worst simultaneously, and it is *already true* — no attacker
action is required for the exposure to exist. That is critical.

Contrast with an over-scoped OAuth app: real blast radius, but the credential is
scoped, revocable, attributable to an app record, and someone made a deliberate
decision to create it. High.

---

## Why severity is assigned rather than computed

An earlier design summed numeric weights per finding — privilege 3, no owner 2,
no MFA 2 — and thresholded the total. It was abandoned, and the reason is worth
recording.

Additive scoring implies the axes are independent and commensurable. They are
not. A service account with Super Admin is not "slightly worse" than one with
Help Desk Admin; it is a different category of problem. Summing weights produces
numbers that look objective, are not, and are harder to argue with in a client
meeting than a stated rule.

So each check assigns severity from explicit conditions written in code, and the
condition appears in the finding's evidence field. A client who disagrees can
point at the specific rule. That is a better conversation than "the model gave it
7.5".

The one place numeric scoring *is* used is service-account detection, because
that genuinely is a probabilistic classification of independent weak signals —
and even there the tool reports the individual signals, not just the total.

---

## What the tool does not claim

- **It does not measure likelihood of exploitation.** No CVSS-style exploitability
  scoring. An audit reports exposure; predicting attacker behaviour is a
  different exercise with different evidence requirements.
- **It does not know your compensating controls.** A network-restricted service
  account with an admin role is safer than an unrestricted one, and the tool
  cannot see that. Severity may be adjusted downward with knowledge the tool
  lacks — which is why remediation text asks questions rather than only issuing
  instructions.
- **It does not weight by business criticality.** All apps are treated equally.
  The provisioning connection to your billing system and the one to your snack
  ordering tool score identically.

Each of these is a reason the report is a starting point for a conversation
rather than a verdict, and the methodology section of every report says so.
