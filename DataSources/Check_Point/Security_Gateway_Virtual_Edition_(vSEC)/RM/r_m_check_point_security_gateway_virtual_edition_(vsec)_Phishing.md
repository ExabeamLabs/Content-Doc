Vendor: Check Point
===================
### Product: [Security Gateway Virtual Edition (vSEC)](../ds_check_point_security_gateway_virtual_edition_(vsec).md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     2      |      3      |    3    |

| Event Type           | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Models |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| web-activity-allowed | <b>T1566.002 - Phishing: Spearphishing Link</b><br> ↳ <b>A-WEB-Phishing</b>: Asset has accessed a domain suspected to be a phishing domain.<br> ↳ <b>WEB-UD-Phishing</b>: User attempted to access a domain which is associated to Phishing<br> ↳ <b>WEB-Phishing</b>: Web activity to a phishing domain.<br><br><b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>A-WEB-Phishing</b>: Asset has accessed a domain suspected to be a phishing domain. |        |