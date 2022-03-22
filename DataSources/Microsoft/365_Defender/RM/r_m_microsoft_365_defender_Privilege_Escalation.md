Vendor: Microsoft
=================
### Product: [365 Defender](../ds_microsoft_365_defender.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      6      |    6    |

| Event Type     | Rules    | Models |
| ---- | ---- | ------ |
| registry-write | <b>T1112 - Modify Registry</b><br> ↳ <b>A-LocalAccountTokenFilterPolicyChange</b>: The LocalAccountTokenFilterPolicy was disabled on the asset.<br> ↳ <b>AccountTokenFilterPolicyChange</b>: The LocalAccountTokenFilterPolicy was disabled<br><br><b>T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control</b><br> ↳ <b>A-LocalAccountTokenFilterPolicyChange</b>: The LocalAccountTokenFilterPolicy was disabled on the asset.<br> ↳ <b>AccountTokenFilterPolicyChange</b>: The LocalAccountTokenFilterPolicy was disabled |        |