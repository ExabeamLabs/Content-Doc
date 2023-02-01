Vendor: Google
==============
### Product: [Cloud Platform](../ds_google_cloud_platform.md)
### Use-Case: [Cloud Data Protection](../../../../UseCases/uc_cloud_data_protection.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   8   |   7    |         3          |      5      |    5    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| gcp-disk-attach       | <b>TA0009 - TA0009</b><br> ↳ <b>GCP-UserAttachDisks-Org-F</b>: First time disk attachment for user    |  • <b>GCP-UserAttachDisks-Org</b>: Users who attached disks in GCP    |
| gcp-disk-create       | <b>TA0009 - TA0009</b><br> ↳ <b>GCP-UserCreateFromSnapshot-Org-F</b>: First time instance/disk creation from a snapshot for user    |  • <b>GCP-UserCreateFromSnapshot-Org</b>: Users who performed disk and instance creations from snapshots in GCP    |
| gcp-instance-create   | <b>TA0009 - TA0009</b><br> ↳ <b>GCP-UserCreateFromSnapshot-Org-F</b>: First time instance/disk creation from a snapshot for user    |  • <b>GCP-UserCreateFromSnapshot-Org</b>: Users who performed disk and instance creations from snapshots in GCP    |
| gcp-snapshot-create   | <b>TA0009 - TA0009</b><br> ↳ <b>GCP-UserCreateSnapshot-Org-F</b>: First time snapshot creation for user    |  • <b>GCP-UserCreateSnapshot-Org</b>: Users who performed snapshot creations in GCP    |
| gcp-storageobject-acl | <b>T1530 - Data from Cloud Storage Object</b><br> ↳ <b>GCP-SetObjectPublic</b>: An object in GCP storage was set to public<br> ↳ <b>GCP-UserSetObjectPublic-Org-F</b>: First time public modification of storage object ACL for user<br> ↳ <b>GCP-UserSetObjectPublic-Bucket-F</b>: First time public modification of storage object ACL for user in this bucket<br><br><b>TA0004 - TA0004</b><br> ↳ <b>GCP-UserSetObjectACL-Org-F</b>: First time modification of storage object ACL for user<br> ↳ <b>GCP-UserSetObjectACL-Bucket-F</b>: First time modification of storage object ACL for user in this bucket |  • <b>GCP-UserSetObjectPublic-Bucket</b>: Users who modified the ACL of storage objects to public in this GCP bucket<br> • <b>GCP-UserSetObjectPublic-Org</b>: Users who modified the ACL of storage objects to public in GCP<br> • <b>GCP-UserSetObjectACL-Bucket</b>: Users who modified the ACL of storage objects in this GCP bucket<br> • <b>GCP-UserSetObjectACL-Org</b>: Users who modified the ACL of storage objects in GCP |