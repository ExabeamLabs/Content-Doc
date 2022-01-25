Vendor: Microsoft
=================
### Product: [Microsoft Windows](../ds_microsoft_microsoft_windows.md)
### Use-Case: [Privileged Asset Abuse](../../../../UseCases/uc_privileged_asset_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |     58      |   58    |

| Event Type   | Rules                                                                                           | Models                                       |
| ------------ | ----------------------------------------------------------------------------------------------- | -------------------------------------------- |
| local-logon  | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| ntlm-logon   | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |