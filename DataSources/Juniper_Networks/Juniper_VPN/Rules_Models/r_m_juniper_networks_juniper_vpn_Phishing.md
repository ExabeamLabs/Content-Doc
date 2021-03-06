Vendor: Juniper Networks
========================
### Product: [Juniper VPN](../ds_juniper_networks_juniper_vpn.md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   2    |     3      |      6      |    6    |

| Event Type           | Rules                                                                                                                                                                                                   | Models                                                                                                  |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| vpn-logout           | <b>T1566 - Phishing</b><br> ↳ <b>EM-FNum-in</b>: Abnormal number of incoming emails<br> ↳ <b>EM-BSum-in</b>: Abnormal size of incoming emails                                                           |  • <b>EM-BSum-in</b>: Sum of bytes in incoming emails<br> • <b>EM-FNum-in</b>: Count of incoming emails |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><b>T1566.002 - Phishing: Spearphishing Link</b><br> ↳ <b>A-WEB-Phishing</b>: Asset has accessed a domain suspected to be a phishing domain. |                                                                                                         |