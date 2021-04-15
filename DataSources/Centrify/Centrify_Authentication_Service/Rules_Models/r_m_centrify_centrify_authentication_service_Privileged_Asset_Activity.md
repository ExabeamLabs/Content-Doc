Vendor: Centrify
================
### Product: [Centrify Authentication Service](../ds_centrify_centrify_authentication_service.md)
### Use-Case: [Privileged Asset Activity](../../../../UseCases/uc_privileged_asset_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      4      |    4    |

| Event Type   | Rules                                                                                           | Models                                       |
| ------------ | ----------------------------------------------------------------------------------------------- | -------------------------------------------- |
| local-logon  | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |