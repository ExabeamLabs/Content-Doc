Vendor: SAP
===========
### Product: [SAP](../ds_sap_sap.md)
### Use-Case: [Cloud Data Protection](../../../../UseCases/uc_cloud_data_protection.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   4   |   4    |         3          |      4      |    4    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| gcp-bucket-create       | <b>T1074 - Data Staged</b><br> ↳ <b>GCP-UserCreateBucket-Org-F</b>: First time storage bucket creation for user    |  • <b>GCP-UserCreateBucket-Org</b>: Users who created storage buckets in GCP    |
| gcp-compute-list        | <b>T1580 - T1580</b><br> ↳ <b>GCP-UserComputeList-Org-F</b>: First time enumeration of compute resources for user          |  • <b>GCP-UserComputeList-Org</b>: Users who listed storage resources in GCP    |
| gcp-instance-screenshot | <b>T1113 - Screen Capture</b><br> ↳ <b>GCP-UserGetScreenshot-Org-F</b>: First time instance screenshot for user    |  • <b>GCP-UserGetScreenshot-Org</b>: Users who captured screenshots in GCP    |
| gcp-storage-list        | <b>T1580 - T1580</b><br> ↳ <b>GCP-UserStorageList-Org-F</b>: First time enumeration of storage buckets or objects for user |  • <b>GCP-UserStorageList-Org</b>: Users who listed storage buckets and objects in GCP |