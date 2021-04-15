Vendor: VMware
==============
### Product: [VMware Carbon Black App Control](../ds_vmware_vmware_carbon_black_app_control.md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |     16      |   16    |

| Event Type                    | Rules                                                                                                                                                                                                        | Models |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| network-connection-failed     | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NETF-TI-IP-Outbound</b>: Outbound failed connection to a known malicious IP<br> ↳ <b>NET-TI-H-Outbound</b>: Outbound connection to a known malicious host |        |
| network-connection-successful | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NET-TI-H-Outbound</b>: Outbound connection to a known malicious host                                                                                      |        |
| process-network               | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NET-TI-H-Outbound</b>: Outbound connection to a known malicious host                                                                                      |        |