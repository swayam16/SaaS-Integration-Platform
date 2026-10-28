@IsTest
private class SyncBridgeNotifierTest {
    private class Capture implements HttpCalloutMock {
        Integer status;
        HttpRequest last;
        Capture(Integer status) { this.status = status; }
        public HttpResponse respond(HttpRequest req) {
            last = req;
            HttpResponse res = new HttpResponse();
            res.setStatusCode(status);
            res.setBody('{"accepted":1}');
            return res;
        }
    }

    @TestSetup
    static void setup() {
        insert new SyncBridge_Settings__c(SetupOwnerId = UserInfo.getOrganizationId(),
            Webhook_Secret__c = 'test-secret', Enabled__c = true);
    }

    @IsTest
    static void sendsSignedNotificationForNewCase() {
        Capture mock = new Capture(202);
        Test.setMock(HttpCalloutMock.class, mock);
        Test.startTest();
        insert new Case(Subject = 'Login fails', Status = 'New', Priority = 'High');
        Test.stopTest();

        Assert.areEqual(1, SyncBridgeNotifier.callouts);
        HttpRequest req = mock.last;
        Assert.areEqual(SyncBridgeNotifier.ENDPOINT, req.getEndpoint());
        String ts = req.getHeader('X-SyncBridge-Timestamp');
        Blob mac = Crypto.generateMac('hmacSHA256', Blob.valueOf(ts + '.' + req.getBody()), Blob.valueOf('test-secret'));
        Assert.areEqual('v1=' + EncodingUtil.convertToHex(mac), req.getHeader('X-SyncBridge-Signature'));
        Map<String, Object> body = (Map<String, Object>) JSON.deserializeUntyped(req.getBody());
        Map<String, Object> ev = (Map<String, Object>) ((List<Object>) body.get('events'))[0];
        Assert.areEqual('Case', ev.get('sobject'));
        Assert.areEqual('CREATE', ev.get('changeType'));
        Map<String, Object> fields = (Map<String, Object>) ev.get('fields');
        Assert.areEqual('Login fails', fields.get('Subject'));
    }

    @IsTest
    static void ignoresUpdatesToUnsyncedFields() {
        Case c = new Case(Subject = 'x', Status = 'New');
        insert c;
        Test.setMock(HttpCalloutMock.class, new Capture(202));
        Test.startTest();
        c.SuppliedEmail = 'someone@example.com';
        update c;
        Test.stopTest();
        Assert.areEqual(0, SyncBridgeNotifier.callouts);
    }

    @IsTest
    static void caseMessagesAreSent() {
        Case c = new Case(Subject = 'x', Status = 'New');
        insert c;
        Capture mock = new Capture(202);
        Test.setMock(HttpCalloutMock.class, mock);
        Test.startTest();
        insert new Case_Message__c(Case__c = c.Id, Body__c = 'On it', Author__c = 'Priya');
        Test.stopTest();
        Assert.isTrue(mock.last.getBody().contains('Case_Message__c'));
    }

    @IsTest
    static void disabledSettingSendsNothing() {
        SyncBridge_Settings__c cfg = SyncBridge_Settings__c.getOrgDefaults();
        cfg.Enabled__c = false;
        update cfg;
        Test.setMock(HttpCalloutMock.class, new Capture(202));
        Test.startTest();
        insert new Case(Subject = 'x');
        Test.stopTest();
        Assert.areEqual(0, SyncBridgeNotifier.callouts);
    }

    @IsTest
    static void serverErrorIsRetryableAndKeepsBody() {
        Case c = new Case(Subject = 'x');
        insert c;
        Test.setMock(HttpCalloutMock.class, new Capture(503));
        SyncBridgeNotifier job = new SyncBridgeNotifier('Case', new List<Id>{ c.Id }, 'UPDATE', 1, null);
        String payload = job.buildPayload();
        Test.startTest();
        System.enqueueJob(new SyncBridgeNotifier('Case', new List<Id>{ c.Id }, 'UPDATE', 2, payload));
        Test.stopTest();
        Assert.areEqual(1, SyncBridgeNotifier.callouts);
    }
}
