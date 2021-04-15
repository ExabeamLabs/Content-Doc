Vendor: Dtex Systems
====================
### Product: [DTEX InTERCEPT](../ds_dtex_systems_dtex_intercept.md)
### Use-Case: [Data Exfiltration via DNS](../../../../UseCases/uc_data_exfiltration_via_dns.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     3      |      9      |    9    |

| Event Type           | Rules                                                                                                                                                                                               | Models |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-created      | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>DNS-Exfiltration-Tools-Exec</b>: Well-known DNS Exfiltration tools were executed.                                                    |        |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><b>T1568 - Dynamic Resolution</b><br> ↳ <b>A-WEB-DynamicDNS</b>: Asset attempted access to a domain generated using Dynamic DNS service |        |