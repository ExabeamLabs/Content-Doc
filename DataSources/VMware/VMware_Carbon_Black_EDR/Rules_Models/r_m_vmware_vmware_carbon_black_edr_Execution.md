Vendor: VMware
==============
### Product: [VMware Carbon Black EDR](../ds_vmware_vmware_carbon_black_edr.md)
### Use-Case: [Execution](../../../../UseCases/uc_execution.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     1      |      2      |    2    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                 | Models |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-created | <b>T1059 - Command and Scripting Interperter</b><br> ↳ <b>PC-PowerShell-SocketCreate</b>: Powershell TCP Socket Creation through Powershell.<br> ↳ <b>PC-PowerShell-ExchangeSnapIns</b>: Exchange Snap-In was imported and run by Powershell.<br> ↳ <b>PC-Powershell-HafniumActivity</b>: Powershell HAFNIUM Activity |        |