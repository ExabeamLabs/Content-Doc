Vendor: Cisco
=============
### Product: [Cisco Adaptive Security Appliance](../ds_cisco_cisco_adaptive_security_appliance.md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   3    |     8      |     10      |   10    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| dlp-email-alert-out  | <b>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol</b><br> ↳ <b>EM-OD-A</b>: Abnormal email domain for organization    |  • <b>EM-OD</b>: Domains per organization    |
| process-created      | <b>T1566.001 - T1566.001</b><br> ↳ <b>A-Exec-Outlook-Temp</b>: A suspicious program was executed in the Outlook temp folder on this asset.<br> ↳ <b>Exec-Outlook-Temp</b>: A suspicious program was executed in the Outlook temp folder.    |    |
| vpn-logout    | <b>T1566 - Phishing</b><br> ↳ <b>EM-FNum-in</b>: Abnormal number of incoming emails<br> ↳ <b>EM-BSum-in</b>: Abnormal size of incoming emails    |  • <b>EM-BSum-in</b>: Sum of bytes in incoming emails<br> • <b>EM-FNum-in</b>: Count of incoming emails |
| web-activity-allowed | <b>T1534 - Internal Spearphishing</b><br> ↳ <b>A-WEB-Phishing</b>: Asset has accessed a domain suspected to be a phishing domain.<br> ↳ <b>WEB-UD-Phishing</b>: User attempted to access a domain which is associated to Phishing<br> ↳ <b>WEB-Phishing</b>: Web activity to a phishing domain.<br><br><b>T1566.002 - Phishing: Spearphishing Link</b><br> ↳ <b>A-WEB-Phishing</b>: Asset has accessed a domain suspected to be a phishing domain.<br> ↳ <b>WEB-URank-Binary</b>: Executable download from first low ranked web domain<br> ↳ <b>WEB-UD-Phishing</b>: User attempted to access a domain which is associated to Phishing<br> ↳ <b>WEB-Phishing</b>: Web activity to a phishing domain.<br><br><b>T1598.003 - T1598.003</b><br> ↳ <b>A-WEB-Phishing</b>: Asset has accessed a domain suspected to be a phishing domain.<br> ↳ <b>WEB-UD-Phishing</b>: User attempted to access a domain which is associated to Phishing<br> ↳ <b>WEB-Phishing</b>: Web activity to a phishing domain.<br><br><b>T1189 - Drive-by Compromise</b><br> ↳ <b>WEB-URank-Binary</b>: Executable download from first low ranked web domain<br><br><b>T1204.001 - T1204.001</b><br> ↳ <b>WEB-URank-Binary</b>: Executable download from first low ranked web domain |    |