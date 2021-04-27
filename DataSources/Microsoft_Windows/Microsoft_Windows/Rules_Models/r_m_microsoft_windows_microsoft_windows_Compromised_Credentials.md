Vendor: Microsoft Windows
=========================
### Product: [Microsoft Windows](../ds_microsoft_windows_microsoft_windows.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     2      |      1      |    1    |

| Event Type      | Rules                                                                                                                                                                                                                        | Models                                  |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| audit-log-clear | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user<br><br><b>T1070.001 - Indicator Removal on Host: Clear Windows Event Logs</b><br> ↳ <b>A-WA-F</b>: Audit log has been cleared on this asset |  • <b>AE-UA</b>: All activity for users |