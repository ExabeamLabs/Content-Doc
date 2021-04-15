Vendor: Zeek
============
### Product: [Zeek Network Security Monitor](../ds_zeek_zeek_network_security_monitor.md)
### Use-Case: [Credential Theft](../../../../UseCases/uc_credential_theft.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |     24      |   24    |

| Event Type   | Rules                                                                                                      | Models |
| ------------ | ---------------------------------------------------------------------------------------------------------- | ------ |
| failed-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-14</b>: Failed logon due to bad credentials                  |        |
| share-access | <b>T1187 - Forced Authentication</b><br> ↳ <b>SA-SCF-Share</b>: A SCF file was created on a network share. |        |