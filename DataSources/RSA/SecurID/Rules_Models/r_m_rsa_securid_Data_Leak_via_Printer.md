Vendor: RSA
===========
### Product: [SecurID](../ds_rsa_securid.md)
### Use-Case: [Data Leak via Printer](../../../../UseCases/uc_data_leak_via_printer.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      3      |    3    |

| Event Type | Rules                                                                                                 | Models                                                  |
| ---------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| vpn-logout | <b>T1052 - Exfiltration Over Physical Medium</b><br> ↳ <b>PR-BSum</b>: Abnormal size of print objects |  • <b>PR-BSum</b>: Sum of bytes of data printed by user |