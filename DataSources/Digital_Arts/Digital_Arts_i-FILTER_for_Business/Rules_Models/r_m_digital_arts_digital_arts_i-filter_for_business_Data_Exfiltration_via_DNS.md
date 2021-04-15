Vendor: Digital Arts
====================
### Product: [Digital Arts i-FILTER for Business](../ds_digital_arts_digital_arts_i-filter_for_business.md)
### Use-Case: [Data Exfiltration via DNS](../../../../UseCases/uc_data_exfiltration_via_dns.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     2      |      2      |    2    |

| Event Type           | Rules                                                                                                                                                                                               | Models |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><b>T1568 - Dynamic Resolution</b><br> ↳ <b>A-WEB-DynamicDNS</b>: Asset attempted access to a domain generated using Dynamic DNS service |        |
| web-activity-denied  | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><b>T1568 - Dynamic Resolution</b><br> ↳ <b>A-WEB-DynamicDNS</b>: Asset attempted access to a domain generated using Dynamic DNS service |        |