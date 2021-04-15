Vendor: NCP
===========
### Product: [NCP](../ds_ncp_ncp.md)
### Use-Case: [Data Leak via Email](../../../../UseCases/uc_data_leak_via_email.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   4    |     1      |      3      |    3    |

| Event Type | Rules                                                                                                                                                                                                                                                                                                                                                                                   | Models                                                                                                                                                                                                                                |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| vpn-logout | <b>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol</b><br> ↳ <b>EM-FNum</b>: Abnormal number of outgoing emails<br> ↳ <b>EM-DNum</b>: Abnormal number of outgoing email domains<br> ↳ <b>EM-BSum-personal</b>: Abnormal size of outgoing emails to personal account<br> ↳ <b>EM-BSum</b>: Abnormal size of outgoing emails |  • <b>EM-BSum</b>: Sum of bytes in outgoing emails<br> • <b>EM-BSum-personal</b>: Sum of bytes in outgoing emails to personal domains<br> • <b>EM-DNum</b>: Number of distinct domains<br> • <b>EM-FNum</b>: Count of outgoing emails |