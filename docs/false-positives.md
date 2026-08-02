# Where the heuristics fail

Service-account detection in this tool is probabilistic. It has to be: Okta has
no field marking an account as non-human, so the only option is inference from
behaviour.

This document is where that method is wrong. It exists because a client who is
told "these four accounts are service accounts", finds the one that isn't, and
then stops trusting the whole report — whereas a client who is told "these four
scored above 0.5 on these specific signals, and here is where that method
breaks" can engage with an individual determination without dismissing the rest.

---

## The scoring model

Four weighted signals, summing to 1.0:

| Signal | Weight |
|---|---|
| Login or display name matches a service-account naming convention | 0.30 |
| No MFA factor enrolled | 0.25 |
| No interactive browser sign-in in the System Log window | 0.30 |
| API events attributed to the actor | 0.15 |

Default threshold **0.50** — two of the four heavier signals. Configurable with
`--threshold` or `NHI_SERVICE_ACCOUNT_THRESHOLD`.

**Why naming isn't the heaviest signal.** It is the most obvious one, and it
would be the wrong choice to lead with. A well-run organisation names its service
accounts clearly, so weighting naming heavily would over-flag exactly the orgs
doing it right, while missing the badly-run org where the NHI is called
`datateam@`. Behavioural signals — no interactive login, no MFA — describe what
the account actually does, and they generalise across naming conventions the tool
has never seen.

---

## False positives — flagged, but human

### Shared team mailboxes and aliases

`support@`, `billing@`, `noreply@` score high: they match naming patterns, often
have no MFA, and rarely sign in interactively. Many are legitimate shared human
accounts.

They are still worth reviewing. A shared human account with no MFA is its own
finding, just a different one — it means multiple people know one password and
nothing attributes an action to an individual.

**Mitigation:** review each flagged account's app assignments. Mail-only
assignments suggest a mailbox.

### Executive assistant and delegated accounts

Sometimes named `assistant-<exec>@` and used through delegation rather than
direct sign-in. Matches "no interactive login" and sometimes naming.

**Mitigation:** check whether a human is assigned to the account in your HR
system. There is no signal available in Okta alone that distinguishes this case.

### Break-glass and emergency admin accounts

`emergency-admin@`, `break-glass@`. By design they are never used and often
MFA-exempt so they work when the MFA provider is the thing that is down.

They will be flagged, and reviewing them is worthwhile — a break-glass account
should be governed with more ceremony than a service account, not less. But
"flagged" is not the same as "misconfigured" for this category.

**Mitigation:** maintain an explicit allowlist of break-glass accounts and
exclude them by convention.

### Newly created human accounts

Someone onboarded yesterday may have no MFA yet and no interactive login yet.
Two signals, 0.55, over threshold.

**Mitigation:** this is the most tractable false positive. Filtering out accounts
created within the last 14 days would remove nearly all of it. It is a known gap,
listed in "planned improvements" below rather than silently patched, because a
report reader deserves to know the current logic.

### Test and training accounts

`test-user-01@`, `demo@`, `training@`. Genuinely dormant, genuinely
unowned, and genuinely worth deleting — but they are not machine identities and
should not be described as such.

---

## False negatives — missed, but non-human

These matter more than the false positives. A false positive costs a
conversation; a false negative means an unowned privileged credential stays
invisible.

### Service accounts named like people

An NHI created as `datasync@example.com`, or worse, one created under a real
employee's name because "we'll fix it later". Loses the naming signal (0.30) and
will not cross the threshold unless every other signal fires.

**Mitigation:** review any account with an admin role and no MFA regardless of
name. Ask the client directly which accounts are automation — the fastest way to
find the ones the tool missed is to ask someone who knows.

### Accounts a human occasionally logs into

A service account whose password is in the team vault, used interactively for
troubleshooting once a quarter. That single sign-in removes the strongest signal
(0.30).

This is a real pattern and a genuinely dangerous one: shared credentials with
both human and machine use, no attribution, and typically no rotation.

**Mitigation:** compare the ratio of API events to interactive sign-ins rather
than treating interactive sign-ins as binary. Listed below as a planned
improvement.

### Accounts with MFA enrolled but machine-driven

Some organisations enrol a TOTP factor on service accounts and store the seed in
a vault. Good practice, and it costs the tool 0.25.

Note this is what the demo fixture's control case (`svc-backup@example.com`)
represents: it is still detected, at 0.75, but reported at low severity because
it is well configured. That is the intended behaviour — a tool that flags
everything at the same severity is not an assessment, it is a list.

### Identities that are not user objects at all

Workflows connections, third-party integrations authenticating via an OAuth app
the tool cannot attribute to a user, and any NHI living outside Okta entirely.
Not a heuristic failure — a scope boundary, stated in every report.

---

## Threshold guidance

| Threshold | Effect | Use when |
|---|---|---|
| 0.30 | Very sensitive. Flags anything with one strong signal. | Initial discovery on a tenant you know nothing about, where you will manually review every result |
| 0.50 | Default. Requires two heavier signals. | Standard assessment |
| 0.75 | Conservative. Roughly three signals. | Large tenants where review capacity is the binding constraint, or when producing a short executive summary |

Run at 0.30 first for your own understanding, then at 0.50 for the deliverable.
The difference between the two lists is itself informative — it tells you how
much of the tenant sits in the ambiguous middle.

---

## How to validate results with a client

The heuristic gets you a candidate list. Confirmation is a conversation, and
these four questions resolve most cases in about ten minutes:

1. **"Which of these accounts does a person log into?"** Resolves shared
   mailboxes and delegated accounts immediately.
2. **"Which team owns each of these?"** If nobody can answer, that is the
   finding — regardless of whether the account turns out to be human or machine.
3. **"Are there automated processes not on this list?"** Surfaces the false
   negatives faster than any amount of tuning.
4. **"Where is the credential for this stored?"** "In the vault" is a good
   answer. "In the Terraform repo" is a different report.

---

## Planned improvements

Listed here rather than quietly implemented, so the report's stated methodology
matches the code as it is today.

- **Account age filter.** Exclude users created in the last 14 days from the
  no-MFA and no-login signals. Removes most new-joiner false positives.
- **Login ratio instead of a boolean.** Score the ratio of API events to
  interactive sign-ins rather than treating any sign-in as disqualifying. Would
  catch the shared human/machine credential case.
- **User-agent analysis on sign-ins.** Already partially implemented — sign-ins
  from `python-requests`, `curl` and similar are excluded from the interactive
  count. Could be extended to headless browser signatures.
- **App assignment shape.** Service accounts typically hold one or two app
  assignments; humans hold many. A weak signal, but an independent one.
- **Group membership.** Absence from any HR-sourced or department group is
  suggestive of a non-human account in orgs that provision groups from an HRIS.
