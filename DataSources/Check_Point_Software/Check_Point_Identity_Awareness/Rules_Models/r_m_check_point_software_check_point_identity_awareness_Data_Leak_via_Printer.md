Vendor: Check Point Software
============================
### Product: [Check Point Identity Awareness](../ds_check_point_software_check_point_identity_awareness.md)
### Use-Case: [Data Leak via Printer](../../../../UseCases/uc_data_leak_via_printer.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      4      |    4    |

| Event Type | Rules                                                                                                 | Models                                                  |
| ---------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| vpn-logout | <b>T1052 - Exfiltration Over Physical Medium</b><br> ↳ <b>PR-BSum</b>: Abnormal size of print objects |  • <b>PR-BSum</b>: Sum of bytes of data printed by user |