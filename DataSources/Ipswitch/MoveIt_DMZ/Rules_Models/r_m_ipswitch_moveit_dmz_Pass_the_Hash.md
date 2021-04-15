Vendor: Ipswitch
================
### Product: [MoveIt DMZ](../ds_ipswitch_moveit_dmz.md)
### Use-Case: [Pass the Hash](../../../../UseCases/uc_pass_the_hash.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      9      |    9    |

| Event Type   | Rules                                                                                                                                                                                                                                                     | Models                             |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| failed-logon | <b>T1550.002 - Use Alternate Authentication Material: Pass the Hash</b><br> ↳ <b>FAIL-PTH-ALERT-sH</b>: Possible unsuccessful pass the hash attack from the source<br> ↳ <b>FAIL-PTH-ALERT-dH</b>: Possible unsuccessful pass the hash attack by the user |  • <b>AE-OHr</b>: Random hostnames |