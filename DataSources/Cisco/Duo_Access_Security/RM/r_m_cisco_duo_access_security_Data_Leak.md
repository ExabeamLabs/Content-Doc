Vendor: Cisco
=============
### Product: [Duo Access Security](../ds_cisco_duo_access_security.md)
### Use-Case: [Data Leak](../../../../UseCases/uc_data_leak.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  11   |   11   |     5      |      7      |    7    |

| Event Type | Rules    | Models    |
| ---------- | ---- | ---- |
| vpn-logout | <b>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB</b><br> ↳ <b>UW-FNum</b>: Abnormal number of files written to USB<br> ↳ <b>UW-BSum</b>: Abnormal amount of data written to USB<br><br><b>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol</b><br> ↳ <b>EM-FNum</b>: Abnormal number of outgoing emails<br> ↳ <b>EM-DNum</b>: Abnormal number of outgoing email domains<br> ↳ <b>EM-BSum-personal</b>: Abnormal size of outgoing emails to personal account<br> ↳ <b>EM-BSum</b>: Abnormal size of outgoing emails<br><br><b>TA0010 - TA0010</b><br> ↳ <b>DLP-UPCOUNT</b>: Abnormal number of DLP policy violations for user<br> ↳ <b>DLP-GPCOUNT</b>: Abnormal number of DLP policy violations for peer group<br> ↳ <b>DLP-BSum</b>: Abnormal amount of data written during DLP policy violation<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>VPN-BSum</b>: Abnormal amount of data uploaded during VPN Session<br><br><b>T1052 - Exfiltration Over Physical Medium</b><br> ↳ <b>PR-NPSum</b>: Abnormal number of pages printed |  • <b>UW-BSum</b>: Sum of bytes written to USB<br> • <b>UW-FNum</b>: Count of assets Files Written to USB<br> • <b>EM-BSum</b>: Sum of bytes in outgoing emails<br> • <b>EM-BSum-personal</b>: Sum of bytes in outgoing emails to personal domains<br> • <b>EM-DNum</b>: Number of distinct domains<br> • <b>EM-FNum</b>: Count of outgoing emails<br> • <b>DLP-BSum</b>: Sum of bytes written during DLP policy violation<br> • <b>DLP-GPCOUNT</b>: Count of DLP policy violations for peer group<br> • <b>DLP-UPCOUNT</b>: Count of DLP policy violations for user<br> • <b>VPN-BSum</b>: Sum of bytes uploaded during VPN<br> • <b>PR-NPSum</b>: Number of pages printed by user |