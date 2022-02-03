Vendor: Cisco
=============
### Product: [Cisco Secure Network Analytics](../ds_cisco_cisco_secure_network_analytics.md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     1      |      1      |    1    |

| Event Type | Rules    | Models    |
| ---------- | ---- | ---- |
| vpn-logout | <b>T1566 - Phishing</b><br> ↳ <b>EM-FNum-in</b>: Abnormal number of incoming emails<br> ↳ <b>EM-BSum-in</b>: Abnormal size of incoming emails |  • <b>EM-BSum-in</b>: Sum of bytes in incoming emails<br> • <b>EM-FNum-in</b>: Count of incoming emails |