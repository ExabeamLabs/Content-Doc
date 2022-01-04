Vendor: Citrix
==============
### Product: [Netscaler WAF](../ds_citrix_netscaler_waf.md)
### Use-Case: [Data Leak](../../../../UseCases/uc_data_leak.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   2    |     1      |      2      |    2    |

| Event Type     | Rules                                                                                                                                                                                                                           | Models                                                                                  |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| print-activity | <b>T1052 - Exfiltration Over Physical Medium</b><br> ↳ <b>PR-UP-F</b>: First print activity from printer for user<br> ↳ <b>PR-UP-A</b>: Abnormal printer for user<br> ↳ <b>PR-UT-TOW</b>: Abnormal print activity time for user |  • <b>PR-UT-TOW</b>: Print activity time for user<br> • <b>PR-UP</b>: Printers for user |