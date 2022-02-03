Vendor: Symantec
================
### Product: [Symantec Email Security.cloud](../ds_symantec_symantec_email_security.cloud.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   2    |     3      |      6      |    6    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| app-activity    | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP    |    |
| process-created-failed | <b>T1021.003 - T1021.003</b><br> ↳ <b>A-PC-ParentName-ProcessName-DCOM-F</b>: First time child process creation for DCOM associated process on this asset.<br> ↳ <b>A-PC-ParentName-ProcessName-DCOM-A</b>: Abnormal child process creation for DCOM associated process on the asset.<br> ↳ <b>A-DCOMActivation-Known</b>: Remote DCOM activation under DcomLaunch service on this asset.<br> ↳ <b>PC-ParentName-ProcessName-DCOM-F</b>: First time child process creation for DCOM associated process<br> ↳ <b>PC-ParentName-ProcessName-DCOM-A</b>: Abnormal child process creation for DCOM associated process.<br> ↳ <b>DCOMActivation-Known</b>: Remote DCOM activation under DcomLaunch service |  • <b>PC-ParentName-ProcessName</b>: Child processes created by a parent process<br> • <b>A-PC-ParentName-ProcessName</b>: Processes for parent parent processes. |
| security-alert         | <b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>A-ALERT-DL</b>: DL Correlation rule alert on asset<br> ↳ <b>ALERT-DL</b>: DL Correlation rule alert on asset accessed by this user    |    |