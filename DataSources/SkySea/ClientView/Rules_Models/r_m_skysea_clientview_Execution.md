Vendor: SkySea
==============
### Product: [ClientView](../ds_skysea_clientview.md)
### Use-Case: [Execution](../../../../UseCases/uc_execution.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     2      |     15      |   15    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                 | Models |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-created | <b>T1059 - Command and Scripting Interperter</b><br> ↳ <b>PC-PowerShell-SocketCreate</b>: Powershell TCP Socket Creation through Powershell.<br> ↳ <b>PC-PowerShell-ExchangeSnapIns</b>: Exchange Snap-In was imported and run by Powershell.<br> ↳ <b>PC-Powershell-HafniumActivity</b>: Powershell HAFNIUM Activity |        |
| share-access    | <b>T1569 - System Services</b><br> ↳ <b>ATP-PSexec</b>: PSExec service was run on the asset by this user.                                                                                                                                                                                                             |        |