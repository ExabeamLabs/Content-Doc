Vendor: Sonicwall
=================
### Product: [Sonicwall](../ds_sonicwall_sonicwall.md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      5      |    5    |

| Event Type                    | Rules                                                                                                                   | Models                                                |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| network-connection-successful | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NET-TI-H-Outbound</b>: Outbound connection to a known malicious host |                                                       |
| vpn-logout                    | <b>T1566 - Phishing</b><br> ↳ <b>EM-BSum-in</b>: Abnormal size of incoming emails                                       |  • <b>EM-BSum-in</b>: Sum of bytes in incoming emails |