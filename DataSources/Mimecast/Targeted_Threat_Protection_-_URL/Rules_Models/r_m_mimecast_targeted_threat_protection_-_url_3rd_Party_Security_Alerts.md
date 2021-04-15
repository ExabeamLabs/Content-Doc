Vendor: Mimecast
================
### Product: [Targeted Threat Protection - URL](../ds_mimecast_targeted_threat_protection_-_url.md)
### Use-Case: [3rd Party Security Alerts](../../../../UseCases/uc_3rd_party_security_alerts.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     1      |      2      |    2    |

| Event Type           | Rules                                                                                                                                                                                                                                                                                                                                      | Models                                                                |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-UD-ALERT-F</b>: First security alert accessing this malicious domain for user<br> ↳ <b>WEB-UD-ALERT-A</b>: Abnormal security alert accessing this malicious domain for user<br> ↳ <b>WEB-UD-ALERT-N</b>: Common security alert on this malicious domain for user |  • <b>WEB-UD-ALERT</b>: Top malicious web domain accessed by the user |
| web-activity-denied  | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-UD-ALERT-F</b>: First security alert accessing this malicious domain for user<br> ↳ <b>WEB-UD-ALERT-A</b>: Abnormal security alert accessing this malicious domain for user<br> ↳ <b>WEB-UD-ALERT-N</b>: Common security alert on this malicious domain for user |  • <b>WEB-UD-ALERT</b>: Top malicious web domain accessed by the user |