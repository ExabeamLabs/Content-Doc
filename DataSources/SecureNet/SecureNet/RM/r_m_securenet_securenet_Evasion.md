Vendor: SecureNet
=================
### Product: [SecureNet](../ds_securenet_securenet.md)
### Use-Case: [Evasion](../../../../UseCases/uc_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      2      |    2    |

| Event Type       | Rules                                                                                                                                  | Models |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| failed-app-login | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP |        |
| vpn-login        | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP                |        |