Vendor: Zoom
============
### Product: [Zoom](../ds_zoom_zoom.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     2      |     11      |   11    |

| Event Type            | Rules                                                                                                                                                      | Models |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity          | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                  |        |
| app-activity-failed   | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP                   |        |
| app-login             | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                  |        |
| authentication-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP                   |        |
| webconference-login   | <b>T1078.004 - Valid Accounts: Cloud Accounts</b><br> ↳ <b>WCA-Ransomware-IP</b>: User performs web conference login from an IP associated with Ransomware |        |