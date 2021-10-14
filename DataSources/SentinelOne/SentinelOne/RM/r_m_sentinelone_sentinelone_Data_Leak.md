Vendor: SentinelOne
===================
### Product: [SentinelOne](../ds_sentinelone_sentinelone.md)
### Use-Case: [Data Leak](../../../../UseCases/uc_data_leak.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   1    |     4      |     14      |   14    |

| Event Type           | Rules                                                                                                                                                                                                                                                                                                                                                                        | Models                                                                          |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| app-activity         | <b>T1114.003 - Email Collection: Email Forwarding Rule</b><br> ↳ <b>EM-InRule-EX</b>: User has created an inbox forwarding rule to forward email to an external domain email<br> ↳ <b>EM-InRule-Public</b>: User has created an inbox forwarding rule to forward email to a public email domain                                                                              |                                                                                 |
| web-activity-allowed | <b>T1030 - Data Transfer Size Limits</b><br> ↳ <b>A-WEB-EXFIL-ASSET</b>: Large amount of data exfiltrated from host<br> ↳ <b>WEB-New-File-20</b>: User with no web activity history has uploaded 20MB or more<br><br><b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-OUa-Browser-F</b>: First activity using this web browser for the organization |  • <b>WEB-OUa-Browser-New</b>: Top web browsers being used in this organization |