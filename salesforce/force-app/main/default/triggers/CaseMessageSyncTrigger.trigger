trigger CaseMessageSyncTrigger on Case_Message__c (after insert, after update) {
    SyncBridgeNotifier.notify('Case_Message__c', Trigger.new, Trigger.isUpdate ? Trigger.oldMap : null);
}
