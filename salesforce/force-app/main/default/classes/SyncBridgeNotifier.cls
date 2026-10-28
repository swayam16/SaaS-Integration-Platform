/**
 * Sends signed change notifications for Cases and Case Messages to SyncBridge.
 *
 * - Runs asynchronously (Queueable), so saving a Case never waits on a callout.
 * - Sends up to 100 records per callout and only for changes to synced fields.
 * - Signs each request: X-SyncBridge-Signature = v1=HMAC-SHA256(secret, "<timestamp>.<body>").
 * - Retries failed callouts up to five times with a growing delay, resending the same body
 *   (same event IDs) so SyncBridge recognises the retries as duplicates.
 * - If notifications are lost anyway (limits, a disabled trigger, a long outage), SyncBridge's
 *   reconciler finds the changes through the REST API within minutes.
 *
 * without sharing: the notification must describe the record as saved, regardless of what the
 * running user can see; only fields that SyncBridge displays are read.
 */
public without sharing class SyncBridgeNotifier implements Queueable, Database.AllowsCallouts {
    @TestVisible static final Integer MAX_ATTEMPTS = 5;
    @TestVisible static final Integer BATCH_SIZE = 100;
    @TestVisible static final String ENDPOINT = 'callout:SyncBridge/webhooks/salesforce';
    @TestVisible static Integer callouts = 0;

    private static final Set<String> CASE_FIELDS = new Set<String>{
        'Subject', 'Status', 'Priority', 'Origin', 'Description', 'OwnerId', 'AccountId'
    };

    private final String sobjectType;
    private final List<Id> recordIds;
    private final String changeType;
    private final Integer attempt;
    private final String body;

    @TestVisible
    private SyncBridgeNotifier(String sobjectType, List<Id> recordIds, String changeType, Integer attempt, String body) {
        this.sobjectType = sobjectType;
        this.recordIds = recordIds;
        this.changeType = changeType;
        this.attempt = attempt;
        this.body = body;
    }

    /** Called from the triggers. */
    public static void notify(String sobjectType, List<SObject> records, Map<Id, SObject> oldMap) {
        SyncBridge_Settings__c cfg = SyncBridge_Settings__c.getOrgDefaults();
        if (cfg == null || cfg.Enabled__c == false || String.isBlank(cfg.Webhook_Secret__c)) {
            return;
        }
        List<Id> ids = new List<Id>();
        for (SObject rec : records) {
            if (oldMap == null || sobjectType != 'Case' || syncedFieldChanged(rec, oldMap.get(rec.Id))) {
                ids.add(rec.Id);
            }
        }
        String change = oldMap == null ? 'CREATE' : 'UPDATE';
        for (Integer i = 0; i < ids.size(); i += BATCH_SIZE) {
            if (Limits.getQueueableJobs() >= Limits.getLimitQueueableJobs()) {
                return; // the reconciler will pick these up
            }
            List<Id> chunk = new List<Id>();
            for (Integer j = i; j < Math.min(i + BATCH_SIZE, ids.size()); j++) {
                chunk.add(ids[j]);
            }
            System.enqueueJob(new SyncBridgeNotifier(sobjectType, chunk, change, 1, null));
        }
    }

    private static Boolean syncedFieldChanged(SObject rec, SObject old) {
        if (old == null) {
            return true;
        }
        for (String f : CASE_FIELDS) {
            if (rec.get(f) != old.get(f)) {
                return true;
            }
        }
        return false;
    }

    public void execute(QueueableContext ctx) {
        String payload = body != null ? body : buildPayload();
        if (payload == null) {
            return;
        }
        Integer status;
        try {
            HttpResponse res = new Http().send(signedRequest(payload));
            callouts++;
            status = res.getStatusCode();
        } catch (CalloutException e) {
            status = 0;
        }
        Boolean retryable = status == 0 || status == 408 || status == 429 || status >= 500;
        if (status >= 200 && status < 300 || !retryable || attempt >= MAX_ATTEMPTS) {
            return;
        }
        if (!Test.isRunningTest()) {
            System.enqueueJob(
                new SyncBridgeNotifier(sobjectType, recordIds, changeType, attempt + 1, payload),
                Math.min(10, attempt * 2)
            );
        }
    }

    @TestVisible
    private HttpRequest signedRequest(String payload) {
        String secret = SyncBridge_Settings__c.getOrgDefaults().Webhook_Secret__c;
        String ts = String.valueOf(Datetime.now().getTime() / 1000);
        Blob mac = Crypto.generateMac('hmacSHA256', Blob.valueOf(ts + '.' + payload), Blob.valueOf(secret));
        HttpRequest req = new HttpRequest();
        req.setEndpoint(ENDPOINT);
        req.setMethod('POST');
        req.setTimeout(10000);
        req.setHeader('Content-Type', 'application/json');
        req.setHeader('X-SyncBridge-Timestamp', ts);
        req.setHeader('X-SyncBridge-Signature', 'v1=' + EncodingUtil.convertToHex(mac));
        req.setBody(payload);
        return req;
    }

    @TestVisible
    private String buildPayload() {
        List<Map<String, Object>> events = new List<Map<String, Object>>();
        if (sobjectType == 'Case') {
            for (Case c : [
                SELECT Id, CaseNumber, Subject, Status, Priority, Origin, Description,
                       Account.Name, Owner.Name, Last_Slack_Actor__c, SystemModstamp
                FROM Case WHERE Id IN :recordIds
            ]) {
                events.add(event(c.Id, c.SystemModstamp, new Map<String, Object>{
                    'CaseNumber' => c.CaseNumber,
                    'Subject' => c.Subject,
                    'Status' => c.Status,
                    'Priority' => c.Priority,
                    'Origin' => c.Origin,
                    'Description' => c.Description == null ? null : c.Description.left(2000),
                    'AccountName' => c.Account?.Name,
                    'OwnerName' => c.Owner?.Name,
                    'Last_Slack_Actor__c' => c.Last_Slack_Actor__c
                }));
            }
        } else {
            for (Case_Message__c m : [
                SELECT Id, Case__c, Body__c, Author__c, Source__c, Slack_Message_Key__c, SystemModstamp
                FROM Case_Message__c WHERE Id IN :recordIds
            ]) {
                events.add(event(m.Id, m.SystemModstamp, new Map<String, Object>{
                    'Case__c' => m.Case__c,
                    'Body__c' => m.Body__c,
                    'Author__c' => m.Author__c,
                    'Source__c' => m.Source__c,
                    'Slack_Message_Key__c' => m.Slack_Message_Key__c
                }));
            }
        }
        if (events.isEmpty()) {
            return null; // deleted before the job ran
        }
        return JSON.serialize(new Map<String, Object>{
            'orgId' => UserInfo.getOrganizationId(),
            'events' => events
        });
    }

    private Map<String, Object> event(Id recordId, Datetime modstamp, Map<String, Object> fields) {
        return new Map<String, Object>{
            'eventId' => UUID.randomUUID().toString(),
            'sobject' => sobjectType,
            'recordId' => recordId,
            'changeType' => changeType,
            'systemModstamp' => modstamp.formatGmt('yyyy-MM-dd\'T\'HH:mm:ss.SSS\'Z\''),
            'fields' => fields
        };
    }
}
