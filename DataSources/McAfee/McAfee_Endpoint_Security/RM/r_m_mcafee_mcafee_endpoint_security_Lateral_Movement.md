Vendor: McAfee
==============
### Product: [McAfee Endpoint Security](../ds_mcafee_mcafee_endpoint_security.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     3      |      9      |    9    |

| Event Type     | Rules    | Models |
| ---- | ---- | ------ |
| local-logon    | <b>T1550.003 - Use Alternate Authentication Material: Pass the Ticket</b><br> ↳ <b>EXPERT-PENTEST-DOMAINS</b>: Possible credentials theft attack detected<br><br><b>T1558 - Steal or Forge Kerberos Tickets</b><br> ↳ <b>EXPERT-PENTEST-DOMAINS</b>: Possible credentials theft attack detected |        |
| security-alert | <b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>A-ALERT-DL</b>: DL Correlation rule alert on asset<br> ↳ <b>ALERT-DL</b>: DL Correlation rule alert on asset accessed by this user    |        |