Vendor: Google
==============
### Product: [Cloud Platform](../ds_google_cloud_platform.md)
### Use-Case: [Cryptomining](../../../../UseCases/uc_cryptomining.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   3   |   1    |         3          |      3      |    3    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| gcp-instance-create  | <b>T1074 - Data Staged</b><br> ↳ <b>GCP-UserCreateInstance-Org-F</b>: First time instance creation for user<br><br><b>T1496 - Resource Hijacking</b><br> ↳ <b>GCP-UserCreateInstance-Org-F</b>: First time instance creation for user    |  • <b>GCP-UserCreateInstance-Org</b>: Users who created an instance in GCP |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-Shadow-Mining</b>: User has browsed to a known coinmining/shadowmining domain<br><br><b>T1496 - Resource Hijacking</b><br> ↳ <b>A-WEB-Shadow-Mining</b>: Host has browsed to a known coinmining/shadowmining domain<br> ↳ <b>WEB-Shadow-Mining</b>: User has browsed to a known coinmining/shadowmining domain |    |
| web-activity-denied  | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-Shadow-Mining</b>: User has browsed to a known coinmining/shadowmining domain<br><br><b>T1496 - Resource Hijacking</b><br> ↳ <b>A-WEB-Shadow-Mining</b>: Host has browsed to a known coinmining/shadowmining domain<br> ↳ <b>WEB-Shadow-Mining</b>: User has browsed to a known coinmining/shadowmining domain |    |