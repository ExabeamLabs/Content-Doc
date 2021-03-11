Vendor: Synology NAS
====================
### Product: [Synology NAS](../ds_synology_nas_synology_nas.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      1      |    1    |

| Event Type   | Rules                                                                                                                                                                                                                                        | Models |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| share-access | <b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><b>T1087 - Account Discovery</b><br> ↳ <b>SA-Bloodhound-2</b>: ADMIN IPC Share samr folder accessed<br> ↳ <b>SA-Bloodhound-Main</b>: Possible Bloodhound Tool Usage by this user |        |