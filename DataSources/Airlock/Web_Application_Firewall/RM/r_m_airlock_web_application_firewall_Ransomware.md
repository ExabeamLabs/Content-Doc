Vendor: Airlock
===============
### Product: [Web Application Firewall](../ds_airlock_web_application_firewall.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      9      |    9    |

| Event Type          | Rules                                                                                                                                    | Models |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP |        |
| app-login           | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                |        |
| failed-app-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP |        |
| file-write          | <b>T1486 - Data Encrypted for Impact</b><br> ↳ <b>FA-EXT</b>: A file has been written and is suspected of Ransomware on host             |        |