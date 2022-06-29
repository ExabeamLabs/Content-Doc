Vendor: CyberArk
================
### Product: [Endpoint Privilege Management](../ds_cyberark_endpoint_privilege_management.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   7   |   2    |     2      |      2      |    2    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| process-alert | <b>TA0002 - TA0002</b><br> ↳ <b>EPA-UP-ALERT-F</b>: First security alert for executing this process by the user<br> ↳ <b>EPA-UP-ALERT-A</b>: Abnormal security alert for executing this process by the user<br> ↳ <b>EPA-UP-ALERT-N</b>: Common security alert for executing this process by the user<br> ↳ <b>EPA-UH-Pen-F</b>: Known pentest tool used<br><br><b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>A-ALERT-Other</b>: Alert on asset<br> ↳ <b>A-ALERT-Critical</b>: Security Alert on a critical asset<br> ↳ <b>A-ALERT-Log4j</b>: Alert associated with an exploitation or post exploitation as seen with Log4j Vulnerability was detected. |  • <b>EPA-UH-Pen</b>: Malicious tools used by user<br> • <b>EPA-UP-ALERT</b>: Processes that triggered alerts for the user |