Vendor: Google
==============
### Product: [Cloud Platform](../ds_google_cloud_platform.md)
### Use-Case: [Cloud Data Protection](../../../../UseCases/uc_cloud_data_protection.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  12   |   11   |         6          |      9      |    9    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| gcp-bucket-create       | <b>T1074 - Data Staged</b><br> ↳ <b>GCP-UserCreateBucket-Org-F</b>: First time storage bucket creation for user    |  • <b>GCP-UserCreateBucket-Org</b>: Users who created storage buckets in GCP    |
| gcp-compute-list        | <b>T1580 - T1580</b><br> ↳ <b>GCP-UserComputeList-Org-F</b>: First time enumeration of compute resources for user    |  • <b>GCP-UserComputeList-Org</b>: Users who listed storage resources in GCP    |
| gcp-disk-attach         | <b>TA0009 - TA0009</b><br> ↳ <b>GCP-UserAttachDisks-Org-F</b>: First time disk attachment for user    |  • <b>GCP-UserAttachDisks-Org</b>: Users who attached disks in GCP    |
| gcp-disk-create         | <b>TA0009 - TA0009</b><br> ↳ <b>GCP-UserCreateFromSnapshot-Org-F</b>: First time instance/disk creation from a snapshot for user    |  • <b>GCP-UserCreateFromSnapshot-Org</b>: Users who performed disk and instance creations from snapshots in GCP    |
| gcp-instance-create     | <b>TA0009 - TA0009</b><br> ↳ <b>GCP-UserCreateFromSnapshot-Org-F</b>: First time instance/disk creation from a snapshot for user    |  • <b>GCP-UserCreateFromSnapshot-Org</b>: Users who performed disk and instance creations from snapshots in GCP    |
| gcp-instance-screenshot | <b>T1113 - Screen Capture</b><br> ↳ <b>GCP-UserGetScreenshot-Org-F</b>: First time instance screenshot for user    |  • <b>GCP-UserGetScreenshot-Org</b>: Users who captured screenshots in GCP    |
| gcp-snapshot-create     | <b>TA0009 - TA0009</b><br> ↳ <b>GCP-UserCreateSnapshot-Org-F</b>: First time snapshot creation for user    |  • <b>GCP-UserCreateSnapshot-Org</b>: Users who performed snapshot creations in GCP    |
| gcp-storage-list        | <b>T1580 - T1580</b><br> ↳ <b>GCP-UserStorageList-Org-F</b>: First time enumeration of storage buckets or objects for user    |  • <b>GCP-UserStorageList-Org</b>: Users who listed storage buckets and objects in GCP    |
| gcp-storageobject-acl   | <b>T1530 - Data from Cloud Storage Object</b><br> ↳ <b>GCP-SetObjectPublic</b>: An object in GCP storage was set to public<br> ↳ <b>GCP-UserSetObjectPublic-Org-F</b>: First time public modification of storage object ACL for user<br> ↳ <b>GCP-UserSetObjectPublic-Bucket-F</b>: First time public modification of storage object ACL for user in this bucket<br><br><b>TA0004 - TA0004</b><br> ↳ <b>GCP-UserSetObjectACL-Org-F</b>: First time modification of storage object ACL for user<br> ↳ <b>GCP-UserSetObjectACL-Bucket-F</b>: First time modification of storage object ACL for user in this bucket |  • <b>GCP-UserSetObjectPublic-Bucket</b>: Users who modified the ACL of storage objects to public in this GCP bucket<br> • <b>GCP-UserSetObjectPublic-Org</b>: Users who modified the ACL of storage objects to public in GCP<br> • <b>GCP-UserSetObjectACL-Bucket</b>: Users who modified the ACL of storage objects in this GCP bucket<br> • <b>GCP-UserSetObjectACL-Org</b>: Users who modified the ACL of storage objects in GCP |