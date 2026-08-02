# Non-human identity in an Okta tenant: a taxonomy

A non-human identity (NHI) is any credential that authenticates software rather
than a person. Service accounts, API tokens, OAuth client credentials, webhook
secrets, provisioning connections. Machine identities now outnumber human ones
in most organisations by a wide margin, and the gap widens every time someone
connects another SaaS tool.

The asymmetry that makes this worth auditing: every company has an accurate,
maintained list of its employees, because HR needs one and people complain when
it is wrong. Almost no company has an equivalent list of its machine identities,
because nothing forces one to exist. Nobody is onboarded, nobody leaves, nobody
complains.

This document catalogues the NHI types that live inside an Okta tenant
specifically — what each one is, where it lives, why it is risky, and what the
audit tool checks.

---

## 1. Org API tokens

**Where:** `/api/v1/api-tokens` · Admin console → Security → API → Tokens

A static bearer token used to authenticate against the Okta Management API. The
string *is* the credential: whoever holds it has its access, with no second
factor and no device binding.

**Why it's risky**

Two properties, both counter-intuitive, and both worth being able to explain
from memory:

**It inherits its creator's privileges.** The token gets the admin privileges the
creating user held at the moment of creation. That binding is made once and never
re-evaluated. If the creator's role is later reduced, the token keeps the
original privileges. If the creator leaves the company and is deprovisioned, the
token keeps working, with the access of a person who no longer works there.
Nothing in the Okta UI shows you this. Offboarding removes the human and leaves
the credential.

**Its expiry is a rolling window, not a deadline.** Tokens are valid for 30 days
from creation *or last use*, whichever is later. Every API call resets the clock.
The consequences run in both directions:

- A token used by a nightly job never expires. It is permanent, and nobody
  decided that.
- A token used quarterly dies silently between uses, and the integration fails
  at the worst possible moment with a bare 401.

**What the tool checks**

| Condition | Severity |
|---|---|
| Creator is DEPROVISIONED or SUSPENDED | critical |
| Never used since creation, window lapsed | medium |
| Used within the last 7 days — effectively immortal | medium |
| Idle 25–30 days — about to expire silently | low |

**Note:** org API tokens cannot be created through the API. That is a deliberate
and correct design decision by Okta, and it is worth knowing because it comes up
in both cert questions and client conversations.

---

## 2. API service integrations (OAuth `client_credentials`)

**Where:** `/api/v1/apps` where `settings.oauthClient.grant_types` contains
`client_credentials` · scopes at `/api/v1/apps/{id}/grants`

An OAuth 2.0 client that authenticates as itself with a client ID and secret. No
user is involved in the flow at all — that is what `client_credentials` means,
and it is why any app using that grant is by definition a machine identity.

**Why it's risky**

This is the *right* way to build a machine integration in Okta, so the finding is
never "you used OAuth". It is about scope.

Okta's scope naming is regular: `okta.<resource>.<read|manage>`. `manage` implies
read and adds write. The failure mode is that granting `okta.users.manage` is
faster than working out which specific read scopes a workload needs, so people
grant it, the integration works, and nobody revisits it. Six months later nobody
can say what the integration writes — which means nobody can say what an attacker
holding its client secret could change.

Okta's own documentation directs you to grant the least-privileged scope that
lets the workload function. Auditing against the vendor's stated guidance is a
much stronger position than auditing against your own opinion.

**What the tool checks**

| Condition | Severity |
|---|---|
| Holds tenant-control scopes (`okta.users.manage`, `okta.roles.manage`, `okta.policies.manage`, …) | high |
| Holds other `.manage` scopes | medium |
| Read-only scopes — reported as correctly configured | low |
| Exists with no scopes granted — an abandoned integration | low |

---

## 3. Service accounts shaped as users

**Where:** `/api/v1/users` — indistinguishable from a human by schema

There is no `isServiceAccount` field in Okta. A service account is just a user
object that happens to be driven by a script. This is the largest NHI category in
most tenants and the only one that requires inference to find.

**Why it's risky**

Because it exists as an ordinary user, it is governed by the controls designed
for humans and by none of the controls you would design for a machine:

- It will not appear in an access review as an integration.
- Nobody is asked to re-certify it, because it does not belong to anyone.
- It survives offboarding, because there is no person to offboard.
- Its password sits in a script, a CI variable, or a config file, and has almost
  certainly never been rotated.
- It typically has no MFA — you cannot prompt a cron job for a push
  notification — so the stored password is the entire control.

**How the tool detects them**

Four weighted signals. None is conclusive alone; the combination carries the
information.

| Signal | Weight | Rationale |
|---|---|---|
| Login or display name matches a service-account naming convention | 0.30 | Suggestive, but well-run orgs name them clearly and badly-run orgs don't — so this cannot be the dominant signal |
| No MFA factor enrolled | 0.25 | Machines can't complete an interactive challenge |
| No interactive browser sign-in in the System Log window | 0.30 | The strongest single signal |
| API events attributed to the actor | 0.15 | Confirms active machine use |

Default threshold: **0.50**. Configurable via `--threshold` or
`NHI_SERVICE_ACCOUNT_THRESHOLD`. See [false-positives.md](false-positives.md)
for where this method fails, which it does.

---

## 4. Admin roles held by non-human identities

**Where:** `/api/v1/users/{id}/roles`

Not a separate identity type — a property of the ones above, and the one that
turns a governance issue into a security incident waiting to happen.

**Why it's risky**

A service account with Super Administrator is the worst single finding available
in an Okta tenant. It combines every weakness at once: full tenant control, no
MFA, a credential stored in plaintext somewhere, and no accountable owner. An
attacker holding it can create themselves a persistent admin account, weaken MFA
policy, and grant access to any connected application. Identity provider
compromise is the standard opening move in recent SaaS breaches precisely because
it collapses every other control simultaneously.

And these grants happen for ordinary reasons. A sync fails, someone grants Super
Admin to unblock it intending to narrow it later, and later never arrives.

**What the tool checks**

| Condition | Severity |
|---|---|
| Suspected NHI holds `SUPER_ADMIN` | critical |
| Suspected NHI holds `ORG_ADMIN`, `APP_ADMIN`, `USER_ADMIN`, `API_ACCESS_MANAGEMENT_ADMIN` | high |
| Suspected NHI holds any other admin role | medium |

---

## 5. Event hooks and inline hooks

**Where:** `/api/v1/eventHooks`, `/api/v1/inlineHooks`

Outbound HTTP calls from Okta to a URL you configure. Event hooks fire
asynchronously after something happens. Inline hooks are called synchronously,
during request processing, and Okta waits for the response.

**Why it's risky**

They do not look like identities, which is why they are almost never inventoried.
But each one is a standing arrangement in which your identity provider sends data
about your users to a third-party endpoint, authenticating with a header someone
configured once and has not looked at since.

Inline hooks are the sharper edge, because they are *in the path*. A
`com.okta.oauth2.tokens.transform` hook can modify the claims placed in an access
token before it is issued. Whoever controls that endpoint has influence over
authorisation decisions in your tenant. There is an availability dimension too:
if the endpoint is slow or down, authentication is affected for real users.

**What the tool checks**

| Condition | Severity |
|---|---|
| Active hook posting over plaintext `http://` | high |
| No authentication header configured on the channel | medium |
| Inline hook active in the authentication path | medium |
| Event hook ACTIVE but never verified — likely abandoned | low |

**Deliberate omission:** the tool does not probe destination URLs. Sending
traffic to a client's third-party endpoints is a side effect an audit should not
have. Read-only covers the client's whole environment, not only their Okta
tenant.

---

## 6. SCIM provisioning connections

**Where:** `/api/v1/apps/{id}/features`

When you enable provisioning on an app, Okta stores a credential for the
downstream SaaS system — an API token, an OAuth grant, an admin account. That
credential must be privileged, because it has to create and delete accounts.

**Why it's risky**

It is invisible. The Okta UI shows a green "Provisioning enabled" toggle, not
"Okta holds an administrative API token for your GitHub organisation". Two
failure modes recur:

**Provisioning left enabled on a deactivated app.** The app was switched off in
Okta; the downstream credential was almost certainly not revoked on the other
side. There is now a live, privileged, unmonitored credential for a system nobody
considers part of the environment any more. Decommissioning that stops at "we
turned it off in Okta" produces exactly this.

**Create enabled, deactivate disabled.** Users flow in and never flow out. When
someone leaves, Okta removes their front-door access but their downstream account
stays active — and if that system supports any authentication path besides SSO (a
local password, a personal access token), the former employee still has access.
This is also precisely what a SOC 2 auditor is testing when they ask you to
demonstrate timely access removal: the control exists on paper and does not fully
execute.

**What the tool checks**

| Condition | Severity |
|---|---|
| Provisioning enabled on an INACTIVE app | high |
| `lifecycleCreate` enabled, `lifecycleDeactivate` disabled | medium |
| Correctly configured — reported as inventory | low |

---

## What this taxonomy deliberately excludes

Okta is one place NHIs live. It is not the only one, and usually not the largest.
Out of scope here, and named explicitly in every report:

- Credentials in CI/CD systems — GitHub Actions secrets, CircleCI contexts
- Cloud IAM roles, access keys and workload identities (AWS, GCP, Azure)
- Secrets committed to source control
- API keys created directly inside downstream SaaS applications
- Okta Workflows connections and their stored credentials
- Kubernetes service accounts and pod identities

Naming the boundary is not a hedge. It tells the reader what the assessment did
not cover, which is what makes the part it did cover trustworthy.
