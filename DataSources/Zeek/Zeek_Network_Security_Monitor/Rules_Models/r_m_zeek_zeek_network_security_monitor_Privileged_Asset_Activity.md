Vendor: Zeek
============
### Product: [Zeek Network Security Monitor](../ds_zeek_zeek_network_security_monitor.md)
### Use-Case: [Privileged Asset Activity](../../../../UseCases/uc_privileged_asset_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |     24      |   24    |

| Event Type   | Rules                                                                                           | Models                                       |
| ------------ | ----------------------------------------------------------------------------------------------- | -------------------------------------------- |
| ntlm-logon   | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets |