Vendor: Extreme Networks
========================
### Product: [Zebra wireless LAN management](../ds_extreme_networks_zebra_wireless_lan_management.md)
### Use-Case: [Pass the Ticket](../../../../UseCases/uc_pass_the_ticket.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     3      |      1      |    1    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                                                                     | Models |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| failed-logon | <b>T1078 - Valid Accounts</b><b>T1550.003 - Use Alternate Authentication Material: Pass the Ticket</b><br> ↳ <b>KL-Tf-fail</b>: Failed logon due to a malformed authentication ticket<br><br><b>T1550.003 - Use Alternate Authentication Material: Pass the Ticket</b><b>T1550.004 - Use Alternate Authentication Material: Web Session Cookie</b><br> ↳ <b>KL-TfG</b>: Rare Kerberos ticket failure code |        |