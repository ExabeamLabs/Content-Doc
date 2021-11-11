Vendor: Forescout
=================
### Product: [Forescout CounterACT](../ds_forescout_forescout_counteract.md)
### Use-Case: [Evasion](../../../../UseCases/uc_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     2      |      4      |    4    |

| Event Type                    | Rules                                                                                                                                                                                                                                       | Models |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity                  | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP                                                                                                                     |        |
| network-connection-failed     | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>A-NETF-TOR-Outbound</b>: Outbound failed connection to a known TOR IP<br><br><b>T1090.004 - T1090.004</b><br> ↳ <b>A-NETF-TOR-Outbound</b>: Outbound failed connection to a known TOR IP |        |
| network-connection-successful | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>A-NET-TOR-Outbound</b>: Outbound connection to a known TOR IP<br> ↳ <b>A-NET-TOR-Inbound</b>: Inbound connection from a known TOR IP                                                     |        |