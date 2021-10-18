Vendor: Sophos
==============
### Product: [Sophos Endpoint Protection](../ds_sophos_sophos_endpoint_protection.md)
### Use-Case: [Evasion](../../../../UseCases/uc_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      9      |    9    |

| Event Type                | Rules                                                                                                                                                                                                                                       | Models |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity-failed       | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP                                                                                                      |        |
| network-connection-failed | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>A-NETF-TOR-Outbound</b>: Outbound failed connection to a known TOR IP<br><br><b>T1090.004 - T1090.004</b><br> ↳ <b>A-NETF-TOR-Outbound</b>: Outbound failed connection to a known TOR IP |        |