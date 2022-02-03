Vendor: Ping Identity
=====================
### Product: [PingOne](../ds_ping_identity_pingone.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     3      |      4      |    4    |

| Event Type    | Rules    | Models |
| ---- | ---- | ------ |
| app-login     | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP    |        |
| service-logon | <b>T1550.003 - Use Alternate Authentication Material: Pass the Ticket</b><br> ↳ <b>EXPERT-PENTEST-DOMAINS</b>: Possible credentials theft attack detected<br><br><b>T1558 - Steal or Forge Kerberos Tickets</b><br> ↳ <b>EXPERT-PENTEST-DOMAINS</b>: Possible credentials theft attack detected |        |