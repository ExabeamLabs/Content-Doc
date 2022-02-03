Vendor: Apache
==============
### Product: [Apache Subversion](../ds_apache_apache_subversion.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |      2      |    2    |

| Event Type          | Rules    | Models |
| ---- | ---- | ------ |
| app-activity-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account     |        |
| file-delete         | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account |        |