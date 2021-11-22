Vendor: VMware
==============
### Product: [VMware NSX](../ds_vmware_vmware_nsx.md)
### Use-Case: [Evasion](../../../../UseCases/uc_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |      2      |    2    |

| Event Type                    | Rules                                                                                                                                  | Models |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity-failed           | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP |        |
| network-connection-successful | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Aggregation</b>: Inbound connection from a known TOR IP                             |        |