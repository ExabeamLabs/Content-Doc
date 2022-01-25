Vendor: Microsoft
=================
### Product: [Microsoft Sysmon](../ds_microsoft_microsoft_sysmon.md)
### Use-Case: [Abnormal Directory Services Activity](../../../../UseCases/uc_abnormal_directory_services_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      7      |    7    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                           | Models |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-created | <b>T1175 - T1175</b><br> ↳ <b>MMC-Spawn-Win-Shell</b>: MMC (Microsoft Management Console) started a Windows command line executable.<br><br><b>T1003 - OS Credential Dumping</b><br> ↳ <b>A-AD-Diagnostic-Tool</b>: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe) on this asset |        |