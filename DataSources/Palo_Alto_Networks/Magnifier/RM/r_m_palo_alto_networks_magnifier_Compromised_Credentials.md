Vendor: Palo Alto Networks
==========================
### Product: [Magnifier](../ds_palo_alto_networks_magnifier.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   2    |     3      |      1      |    1    |

| Event Type    | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Models                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| remote-access | <b>T1078.002 - T1078.002</b><br> ↳ <b>SL-UH-F</b>: First access from asset for a service account<br> ↳ <b>SL-UH-A</b>: Abnormal access from asset for a service account<br><br><b>T1558 - Steal or Forge Kerberos Tickets</b><br> ↳ <b>EXPERT-PENTEST-DOMAINS</b>: Possible credentials theft attack detected<br><br><b>T1021 - Remote Services</b><br> ↳ <b>A-RLA-AA-F</b>: First asset-to-asset communication<br> ↳ <b>A-RLA-AA-A</b>: Abnormal asset-to-asset communication |  • <b>AL-UsH</b>: Source hosts per User<br> • <b>A-RLA-AA</b>: Asset to asset communication (DISABLED) |