Vendor: Digital Guardian
========================
### Product: [Digital Guardian Endpoint Protection](../ds_digital_guardian_digital_guardian_endpoint_protection.md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   3   |   1    |         2          |      2      |    2    |

| Event Type          | Rules    | Models    |
| ---- | ---- | ---- |
| dlp-email-alert-out | <b>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol</b><br> ↳ <b>EM-OD-A</b>: Abnormal email domain for organization    |  • <b>EM-OD</b>: Domains per organization |
| process-created     | <b>T1566.001 - T1566.001</b><br> ↳ <b>A-Exec-Outlook-Temp</b>: A suspicious program was executed in the Outlook temp folder on this asset.<br> ↳ <b>Exec-Outlook-Temp</b>: A suspicious program was executed in the Outlook temp folder. |    |