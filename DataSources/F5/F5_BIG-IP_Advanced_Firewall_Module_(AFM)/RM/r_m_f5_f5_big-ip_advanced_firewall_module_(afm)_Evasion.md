Vendor: F5
==========
### Product: [F5 BIG-IP Advanced Firewall Module (AFM)](../ds_f5_f5_big-ip_advanced_firewall_module_(afm).md)
### Use-Case: [Evasion](../../../../UseCases/uc_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     1      |      2      |    2    |

| Event Type                    | Rules                                                                                                                                                                                   | Models |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity                  | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP                                                                 |        |
| network-connection-successful | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>A-NET-TOR-Outbound</b>: Outbound connection to a known TOR IP<br> ↳ <b>A-NET-TOR-Inbound</b>: Inbound connection from a known TOR IP |        |