# Architecture

![SyncBridge architecture](architecture.svg)

SyncBridge is a set of small AWS Lambda functions behind one HTTPS hostname. Everything runs in
the customer's AWS account, one deployment per customer (`infra/template.yaml`).

## Request paths

| Path | Function | Job |
|---|---|---|
| `/webhooks/salesforce`, `/webhooks/slack/*` | `webhooks` | Verify the HMAC signature and timestamp, put the event on SQS, answer 202 in milliseconds |
| `/api/*`, `/saml/*`, `/oauth/*` | `api` | Admin console backend, SAML sign-in, OAuth connections |
| `/scim/v2/*` | `scim` | Okta user and group provisioning |
| SQS event source | `worker` | Apply events to Salesforce or Slack, exactly once |
| EventBridge, every 5 minutes | `reconcile` | Find Salesforce changes whose webhook never arrived |

CloudFront serves the React console from S3 and forwards the paths above to API Gateway, so the
console, cookies and every endpoint share one origin.

## The two sync directions

**Salesforce → Slack.** A Case trigger queues an Apex job that posts a signed batch of changes
(`salesforce/force-app`). The worker renders the Case as a Block Kit message: the first change
posts it, later changes edit the same message in place, and agent-written Case Messages become
replies in its thread. A hash of the rendered message is kept, so changes nobody would see in
Slack cost no API call.

**Slack → Salesforce.** A reply in a Case's thread becomes a `Case_Message__c` record through an
upsert keyed by `channel:ts`, and edits update the same record. The Escalate, Close and Reopen
buttons PATCH the Case. Salesforce stays the system of record: the Slack message changes only when
the resulting Case update comes back through the trigger.

## Exactly-once writes on an at-least-once pipeline

Salesforce callouts are retried, Slack retries events it doesn't see acknowledged in three
seconds, SQS redelivers, and Lambda functions get killed mid-flight. SyncBridge assumes every
event can arrive more than once, late and out of order, and stacks five defences
(`src/syncbridge/sync/engine.py`):

1. **Idempotency keys** describe what an event means, not how it arrived:
   `sf:Case:<id>:<SystemModstamp>`, `slack:msg:<channel>:<ts>:<edit ts>`,
   `slack:action:<action_ts>:<user>`. Claiming a key is a DynamoDB conditional put with a lease;
   a duplicate finds it completed and is acknowledged without work.
2. **Record locks** (another conditional write) serialise events for the same record.
3. **Version guards** drop anything older than what is already synced.
4. **Idempotent writes.** Salesforce writes are upserts by external ID or PATCHes. Slack has no
   idempotency key on `chat.postMessage`, so the mapping row is reserved as `PENDING` before
   posting, and every message carries Slack message metadata naming its record. After a timeout,
   a 5xx or a crash, the worker searches the channel (or thread) for that metadata before it
   would ever post again.
5. **Echo suppression.** SyncBridge's own posts and Slack-sourced Case Messages are never synced
   back.

The idempotency key alone is not enough. A worker can crash after a write and before it marks the
key done; when the lease expires another worker runs the event again. Layer 4 is what makes that
second run harmless, and the failure test injects exactly this crash 900+ times
([failure-testing.md](failure-testing.md)).

## Failure handling

- **Retries**: exponential backoff with full jitter; `Retry-After` honoured on 429s. Waits longer
  than ten seconds are handed back to SQS (`ChangeMessageVisibility`) rather than slept inside
  a billed Lambda.
- **Circuit breakers** per API stop calls during an outage and probe periodically.
- **Partial batch failures**: the worker reports only failed messages back to SQS.
- **Failed syncs**: permanent errors and messages that keep failing are recorded with the reason
  and can be retried from the console. A real SQS DLQ catches anything that crashes the worker
  outright and raises an alarm.
- **Reconciliation** queries Salesforce on `SystemModstamp` with an overlap window, so lost
  webhooks are recovered within minutes.
- **Token refresh** is single-flight: one worker refreshes, the others reuse the new token.

## State

One DynamoDB table (single-table design, on-demand, point-in-time recovery, TTL for expiry).
Point lookups use `pk = "<table>#<key>"`; small lists (users, groups, audit, failed syncs) use
`pk = "<table>", sk = "<key>"`. Expired items are filtered on read and in conditions because
DynamoDB deletes them lazily. The in-memory store used locally and in tests implements the same
conditional-write semantics, and both pass the same contract tests.

## Identity

- **SAML 2.0** service provider with signature verification against the pinned Okta certificate,
  claims read only from the signed element, and audience, recipient, time, InResponseTo and replay
  checks (`src/syncbridge/saml/sp.py`).
- **SCIM 2.0** Users and Groups with filters, paging and Okta's and Entra ID's PATCH styles
  (`src/syncbridge/scim/`). Okta groups map to roles; deactivation revokes live sessions.
- **Sessions** are server-side, hashed at rest, with CSRF tokens on every write.

See [security-faq.md](security-faq.md) for the full list of controls.

## Scaling and limits

- The worker's SQS concurrency is capped (`WorkerConcurrency`, default 10) to stay inside
  Salesforce's concurrent request limit and Slack's per-method rate tiers. A message posted per
  Case means Slack's `chat.postMessage` limit (about one per second per channel) is the practical
  ceiling for brand-new Cases; updates and replies are spread across other methods.
- A Salesforce change costs no Salesforce API calls (the webhook carries the fields); a Slack
  reply or button press costs one. The reconciler costs one query per 2,000 changed records.
- Lambda, SQS and DynamoDB on-demand scale without configuration; the console is static files on
  CloudFront.
