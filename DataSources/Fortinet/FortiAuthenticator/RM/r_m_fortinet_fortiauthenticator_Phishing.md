Vendor: Fortinet
================
### Product: [FortiAuthenticator](../ds_fortinet_fortiauthenticator.md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     1      |      2      |    2    |

| Event Type | Rules                                                                                                                                             | Models                                                                                                 |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| vpn-logout | <b>T1566 - Phishing</b><br> ↳ <b>EM-DNum</b>: Abnormal number of outgoing email domains<br> ↳ <b>EM-BSum-in</b>: Abnormal size of incoming emails |  • <b>EM-BSum-in</b>: Sum of bytes in incoming emails<br> • <b>EM-DNum</b>: Number of distinct domains |