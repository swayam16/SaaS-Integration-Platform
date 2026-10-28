# SyncBridge security FAQ

Answers for security reviewers and IT teams evaluating SyncBridge. Everything here describes how
the code in this repository behaves; file references point to where it happens.

## Hosting and data

**Where does SyncBridge run, and who can see our data?**
In your own AWS account and region, deployed from `infra/template.yaml`. Each customer gets a
separate deployment: no shared database, queue or keys with anyone else. Nothing is sent to the
SyncBridge vendor; there is no telemetry.

**What data does SyncBridge read?**
From Salesforce: Case number, subject, status, priority, origin, description (first 2,000
characters), account name and owner name, plus Case Messages. From Slack: the text, author and
timestamp of replies inside the threads SyncBridge itself started, and the display name of people
who reply or press buttons. It does not read other channels, direct messages, files or
attachments.

**What does it store, and for how long?**

| Data | Where | Kept |
|---|---|---|
| Which Slack message belongs to which Salesforce record (IDs, timestamps, a hash of the rendered message) | DynamoDB | While the record is synced |
| Idempotency records (event key, outcome, record IDs) | DynamoDB | 7 days |
| Activity feed (record ID, direction, outcome, delay) | DynamoDB | 7 days |
| Events waiting to be processed (contain Case fields or reply text) | SQS | Normally seconds; at most 14 days |
| Failed syncs (contain the event) | DynamoDB | Until retried or discarded |
| OAuth tokens for Salesforce and Slack | DynamoDB, encrypted | Until disconnected |
| People provisioned by Okta (name, email, groups, active flag) | DynamoDB | Until deprovisioned |
| Console sessions | DynamoDB | 8 hours at most, 30 minutes idle |
| Audit log | DynamoDB | 1 year |

Case and message content is not written to logs. Logs carry record IDs, outcomes and error codes.

**How do we delete everything?**
Disconnect both apps in the console (revokes the tokens), then delete the stack and the
DynamoDB table (it has deletion protection, which you turn off first). See *Removing SyncBridge*
in the setup guide.

## Encryption

**In transit?**
TLS everywhere. CloudFront accepts TLS 1.2 and above only (`TLSv1.2_2021` policy) and redirects
HTTP to HTTPS; it reaches API Gateway over HTTPS. Calls to Salesforce and Slack are HTTPS.
Responses carry HSTS (two years), `X-Content-Type-Options`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer` and a restrictive Content-Security-Policy.

**At rest?**
A customer-managed KMS key, created by the stack with yearly rotation, encrypts the DynamoDB table,
both SQS queues, the Secrets Manager secret and the alarm topic. OAuth tokens are encrypted a
second time before they are stored (`src/syncbridge/crypto.py`): each token set gets its own
AES-256-GCM data key from KMS `GenerateDataKey`, and only the KMS-encrypted data key is kept
next to the ciphertext. The KMS encryption context and the GCM associated data both name the
purpose and the provider, so a ciphertext copied into another record will not decrypt. Outside
local development the service refuses to start without a KMS key.

**Who can decrypt?**
Each SyncBridge function has its own IAM role with only the KMS actions it needs for the table,
queue and secret it uses. Nobody else can decrypt unless an IAM administrator in your account
grants it; the key policy leaves that decision to your account. Disabling the key stops
SyncBridge and makes the stored tokens unreadable.

## Connections to Salesforce and Slack

**What permissions does SyncBridge ask for?**
Salesforce: the `api` and `refresh_token` scopes, used as a dedicated integration user with the
*SyncBridge Integration* permission set: read and edit Cases, create and edit Case Messages, no
delete, no other objects. Slack: `chat:write`, `channels:history`, `groups:history` and
`users:read`; the app only acts in channels it is invited to.

**How are the OAuth flows protected?**
The `state` parameter is random, single-use, expires after ten minutes and is tied to the admin
who started the flow (`src/syncbridge/oauth.py`). The Salesforce flow uses PKCE (S256). Only
admins can start or complete a connection, and every connection and disconnection is audited.
Disconnecting revokes the token with the provider before deleting it.

**How are incoming webhooks authenticated?**
Every request is signed with HMAC-SHA256 and a timestamp: Slack's `v0` signature with your app's
signing secret, and an equivalent `v1` signature from the Salesforce trigger with a secret only you
know, kept in a protected custom setting. Requests older than five minutes are rejected to stop
replays; signatures are compared in constant time; Slack events from another workspace are
ignored. Unsigned or badly signed requests get a 401 and never reach the queue.

**Can someone press a button on a Slack message to change an arbitrary Case?**
No. A button is accepted only if it was pressed on the message SyncBridge posted for that same
Case, in the configured channel, and the click carries Slack's signature. The update is applied as
the integration user, and the Slack user's name is recorded on the Case (`Last_Slack_Actor__c`).

## Admin console access

**How do people sign in?**
Only through Okta (SAML 2.0). There are no local passwords, so your Okta policies (MFA, device
trust, session length) apply. The service provider (`src/syncbridge/saml/sp.py`):

- verifies the signature against the Okta certificate you configured (RSA-SHA256; SHA-1 refused),
  and reads claims only from the element that was actually signed, which defeats XML signature
  wrapping;
- requires exactly one assertion and rejects encrypted ones it can't read rather than skipping them;
- checks issuer, destination, audience, recipient, validity window (two minutes of clock skew) and
  bearer confirmation;
- accepts a response only for a login it started in the last ten minutes, once, and refuses
  IdP-initiated logins unless you enable them;
- records each assertion ID until it expires, so a captured response can't be replayed;
- parses XML with DTDs, external entities and network access disabled, and strips comments
  before reading (the NameID truncation attack).

Each of these has a test in `tests/test_saml.py`.

**Who gets in, and with what rights?**
Only people Okta has provisioned to SyncBridge over SCIM and who are active. Roles come from Okta
groups:

| Role | Can |
|---|---|
| Viewer | See sync health, activity, failed syncs, connections and settings |
| Operator | Also retry failed syncs and run a reconciliation |
| Admin | Also connect and disconnect apps, change settings, discard failed syncs, read the audit log and the list of people |

Every API call checks the role on the server; the console only hides what you can't use.

**What happens when someone leaves?**
When Okta deactivates or deletes them, SyncBridge ends all their console sessions at once. Group
changes update the role of their live sessions.

**How are sessions protected?**
A random 256-bit ID in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie with the `__Host-` prefix.
The server stores only a SHA-256 of the ID. Sessions end after 30 idle minutes or 8 hours, or
earlier if Okta's session ends sooner. Every state-changing request needs a per-session CSRF token
and a same-origin `Origin` header. Post-login redirects only go to relative paths on the same site.

**How is the SCIM endpoint protected?**
With a bearer token you generate. SyncBridge stores only its SHA-256 and compares in constant
time. The SCIM function has a concurrency cap of five.

## Reliability as a security property

**Can a retry or an outage create duplicate records or messages?**
Not in our failure testing. Every write is idempotent: Salesforce writes are upserts by external
ID or PATCHes, and each Slack post is reserved before it is sent and recovered by message metadata
if the response is lost. A run of 10,000 Cases with duplicate webhooks, API timeouts after the
write had succeeded, outages and 900+ simulated worker crashes ended with no duplicates and every
record matching on both sides; see [failure-testing.md](failure-testing.md).

**What if a webhook is lost?**
Every five minutes a reconciler asks Salesforce for recent changes and re-sends any record whose
Slack copy is missing or out of date.

## Monitoring and audit

- **Audit log** in the console (admins): sign-ins and failures with the reason, refusals,
  provisioning events, connections, settings changes, retries and discards, with source IP.
- **CloudWatch**: structured JSON logs from every function, API Gateway access logs (90 days),
  X-Ray tracing, and optional alarms for dead-lettered messages, queue backlog and worker errors.
- **Backups**: DynamoDB point-in-time recovery (35 days) and deletion protection.

## Things to know

- SyncBridge is not independently certified (SOC 2, ISO 27001). Because it runs entirely in your
  AWS account, it falls under your account's existing controls and audits.
- Encrypted SAML assertions are not supported; use TLS (always on) with signed, unencrypted
  assertions, Okta's default.
- Slack token rotation is supported but off in the default manifest.
- Report a vulnerability to the maintainer privately rather than in a public issue.
