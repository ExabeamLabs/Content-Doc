Vendor: Dtex Systems
====================
### Product: [DTEX InTERCEPT](../ds_dtex_systems_dtex_intercept.md)
### Use-Case: [Data Exfiltration via Web](../../../../UseCases/uc_data_exfiltration_via_web.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     4      |      9      |    9    |

| Event Type           | Rules                                                                                                                                                                                                         | Models |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-created      | <b>T1505.003 - Server Software Component: Web Shell</b><br> ↳ <b>A-WebShell-WebServer</b>: Possible web server web shell detected on this asset                                                               |        |
| web-activity-allowed | <b>T1030 - Data Transfer Size Limits</b><br> ↳ <b>A-WEB-EXFIL-ASSET</b>: Large amount of data exfiltrated from host<br> ↳ <b>WEB-New-File-20</b>: User with no web activity history has uploaded 20MB or more |        |