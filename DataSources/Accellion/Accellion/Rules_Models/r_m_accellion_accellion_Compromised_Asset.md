Vendor: Accellion
=================
### Product: [Accellion](../ds_accellion_accellion.md)
### Use-Case: [Compromised Asset](../../../../UseCases/uc_compromised_asset.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     1      |     10      |   10    |

| Event Type | Rules                                                                                                                                                                                                                                                                                                                                                                          | Models                                                                                   |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| file-read  | <b>T1003.003 - T1003.003</b><br> ↳ <b>A-NTDS-Access-F</b>: The NTDS database was accessed from a new location on this asset.<br> ↳ <b>A-NTDS-Access-A</b>: The NTDS database was accessed from a non default location on this asset.<br> ↳ <b>A-NTDS-Access</b>: The NTDS database was accessed from a non default location without 'ntds.dit' in the file path on this asset. |  • <b>A-NTDS-Access</b>: Models the amount of accesses to paths that are related to NTDS |