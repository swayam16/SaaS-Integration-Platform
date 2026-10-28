trigger CaseSyncTrigger on Case (after insert, after update) {
    SyncBridgeNotifier.notify('Case', Trigger.new, Trigger.isUpdate ? Trigger.oldMap : null);
}
