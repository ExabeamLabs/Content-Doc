Vendor: HelpSystems
===================
### Product: [Powertech Identity Access Manager (BoKs)](../ds_helpsystems_powertech_identity_access_manager_(boks).md)
### Use-Case: [Pass the Hash](../../../../UseCases/uc_pass_the_hash.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     1      |      7      |    7    |

| Event Type   | Rules                                                                                                                                                                                                                             | Models                                                                              |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| remote-logon | <b>T1550.002 - Use Alternate Authentication Material: Pass the Hash</b><br> ↳ <b>A-PTH-ALERT-sH</b>: Possible pass the hash attack from this source host<br> ↳ <b>PTH-ALERT-sH</b>: Possible pass the hash attack from the source |  • <b>AE-OHr</b>: Random hostnames<br> • <b>A-AE-OHr</b>: Random hostnames on asset |