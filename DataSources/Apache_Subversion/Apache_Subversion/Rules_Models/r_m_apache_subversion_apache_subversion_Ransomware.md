Vendor: Apache Subversion
=========================
### Product: [Apache Subversion](../ds_apache_subversion_apache_subversion.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |      2      |    2    |

| Event Type          | Rules                                                                                                                                    | Models |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity        | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                |        |
| app-activity-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP |        |