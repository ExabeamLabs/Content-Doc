Vendor: Fortinet
================
### Product: [Fortinet Enterprise Firewall](../ds_fortinet_fortinet_enterprise_firewall.md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |      6      |    6    |

| Event Type                    | Rules                                                                                                                          | Models |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------ |
| netflow-connection            | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NET-TI-H-Outbound</b>: Outbound connection to a known malicious host        |        |
| network-connection-failed     | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NETF-TI-IP-Outbound</b>: Outbound failed connection to a known malicious IP |        |
| network-connection-successful | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NET-TI-H-Outbound</b>: Outbound connection to a known malicious host        |        |