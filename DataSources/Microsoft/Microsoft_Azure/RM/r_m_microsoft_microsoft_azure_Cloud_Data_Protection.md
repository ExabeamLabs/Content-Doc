Vendor: Microsoft
=================
### Product: [Microsoft Azure](../ds_microsoft_microsoft_azure.md)
### Use-Case: [Cloud Data Protection](../../../../UseCases/uc_cloud_data_protection.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   5   |   5    |         4          |      6      |    6    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| azure-blob-read      | <b>T1078.004 - Valid Accounts: Cloud Accounts</b><br> ↳ <b>B-Azure-UserAgent-StorageAccount-F</b>: First time user agent seen when accessing this Azure storage account    |  • <b>B-Azure-UserAgent-StorageAccount</b>: Azure - user agents per storage account    |
| azure-blob-write     | <b>T1078.004 - Valid Accounts: Cloud Accounts</b><br> ↳ <b>B-Azure-UserAgent-StorageAccount-F</b>: First time user agent seen when accessing this Azure storage account    |  • <b>B-Azure-UserAgent-StorageAccount</b>: Azure - user agents per storage account    |
| azure-container-acl  | <b>T1078.004 - Valid Accounts: Cloud Accounts</b><br> ↳ <b>B-Azure-UserAgent-StorageAccount-F</b>: First time user agent seen when accessing this Azure storage account<br><br><b>T1204 - User Execution</b><br> ↳ <b>Azure-UserSetContainerAcl-Org-F</b>: First time Azure container ACL modification for user |  • <b>B-Azure-UserAgent-StorageAccount</b>: Azure - user agents per storage account<br> • <b>Azure-UserSetContainerAcl-Org</b>: Azure - users who set containers ACLs |
| azure-disk-write     | <b>TA0009 - TA0009</b><br> ↳ <b>Azure-UserDiskFromSnapshot-Org-F</b>: First time Azure disk creation from snapshot    |  • <b>Azure-UserDiskFromSnapshot-Org</b>: Azure - users who created disks from snapshots    |
| azure-snapshot-write | <b>TA0009 - TA0009</b><br> ↳ <b>Azure-UserSnapshotWrite-Org-F</b>: First time Azure snapshot write operation    |  • <b>Azure-UserSnapshotWrite-Org</b>: Azure - users who created/updated snapshots    |
| azure-storage-list   | <b>T1078.004 - Valid Accounts: Cloud Accounts</b><br> ↳ <b>B-Azure-UserAgent-StorageAccount-F</b>: First time user agent seen when accessing this Azure storage account<br><br><b>T1580 - T1580</b><br> ↳ <b>Azure-UserStorageList-Org-F</b>: First time Azure storage enumeration    |  • <b>B-Azure-UserAgent-StorageAccount</b>: Azure - user agents per storage account<br> • <b>Azure-UserStorageList-Org</b>: Azure - users who enumerated storage      |