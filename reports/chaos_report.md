# Failure test report

Seed 7 · 10,000 Salesforce Cases created over 30 virtual minutes · run time 75.6 s

The real platform code (signed webhook routes, queue, worker, sync engine, API clients, reconciler) ran against the Salesforce and Slack simulators with faults injected at every layer. Afterwards both systems were audited record by record.

## Result

| Check | Result |
|---|---:|
| Records synced (Cases + case messages both ways) | **17,107** |
| Duplicate Slack messages for a Case | **0** |
| Duplicate Slack thread replies | **0** |
| Duplicate Case_Message__c records in Salesforce | **0** |
| Cases missing in Slack | 0 |
| Slack replies missing in Salesforce | 0 |
| Slack Case messages that differ from final Salesforce state | 0 |
| Salesforce case messages that differ from final Slack text | 0 |

## What was synced

- 10,000 Cases → one Slack message each, kept up to date through 30,984 Salesforce change notifications
- 3,593 agent messages from Salesforce → Slack thread replies
- 3,514 Slack thread replies (+668 edits) → Case_Message__c records
- 2,467 Slack button clicks (escalate / close / reopen) → Case updates

## Faults injected

| Layer | Fault | Count |
|---|---|---:|
| Salesforce webhooks | delivered twice (callout retry) | 2,958 |
| Salesforce webhooks | never delivered | 321 |
| Salesforce webhooks | delayed up to 20 s (reordered) | all |
| Slack events | redelivered (X-Slack-Retry-Num) | 604 |
| Salesforce API | write committed, then timeout or 500 | 145 |
| Salesforce API | 503 / connection refused / row lock / limit | 160 |
| Salesforce API | full outage (1.5 min) | 12 calls refused |
| Salesforce API | access token expired | 2 |
| Slack API | message posted, then timeout or 500 | 516 |
| Slack API | 429 with Retry-After | 322 |
| Slack API | 503 / connection reset | 454 |
| Slack API | full outage (3.0 min) | 16 calls refused |
| Worker | hard crash mid-message (no cleanup) | 924 |

## How the platform handled them

- **3,583** duplicate deliveries recognised by idempotency key and acknowledged without a write
- **453** posts whose outcome was unknown (timeout after Slack accepted it, or a crash right after posting) found again through message metadata instead of being posted twice
- 2,157 out-of-order events dropped by version guards; 4,241 echoes of our own writes ignored
- 1,202 inline retries with jittered backoff; 345 rate-limit responses honoured via Retry-After
- Circuit breakers opened 5× for Salesforce and 9× for Slack, skipping 13,162 calls during outages
- 15,150 queue redeliveries (crashes, deferrals)
- 23 messages dead-lettered during the outages, all replayed afterwards (0 left)
- Reconciler scanned 13,593 records and re-enqueued 179 whose webhook never arrived

## Baseline: the same run without the safeguards

Same seed and faults, with the engine in `naive` mode: check the mapping table, then write, and retry failed calls as they are (no idempotency keys, record locks, PENDING reservations, metadata recovery or upserts).

| Check | With safeguards | Naive |
|---|---:|---:|
| Duplicate Slack messages for a Case | 0 | 326 |
| Duplicate Slack thread replies | 0 | 114 |
| Duplicate Case_Message__c records | 0 | 126 |
| Slack Case messages out of date | 0 | 152 |
| Salesforce messages out of date | 0 | 24 |
| Slack replies missing in Salesforce | 0 | 0 |

## Traffic

40,874 webhook deliveries · 56,224 queue receives · 7,008 Salesforce API calls · 31,556 Slack API calls · 58 virtual minutes

Reproduce: `syncbridge chaos --cases 10000 --seed 7 --baseline`
