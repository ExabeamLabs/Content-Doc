Vendor: Cisco
=============
### Product: [AnyConnect](../ds_cisco_anyconnect.md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      3      |    3    |

| Event Type      | Rules                                                                                                                   | Models                                                |
| --------------- | ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| process-network | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NET-TI-H-Outbound</b>: Outbound connection to a known malicious host |                                                       |
| vpn-logout      | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>EM-BSum-in</b>: Abnormal size of incoming emails         |  • <b>EM-BSum-in</b>: Sum of bytes in incoming emails |