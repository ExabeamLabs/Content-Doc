Vendor: BeyondTrust
===================
### Product: [BeyondTrust Privileged Identity](../ds_beyondtrust_beyondtrust_privileged_identity.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   0    |     1      |      4      |    4    |

| Event Type   | Rules                                                                                                                     | Models |
| ------------ | ------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP |        |
| app-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP |        |