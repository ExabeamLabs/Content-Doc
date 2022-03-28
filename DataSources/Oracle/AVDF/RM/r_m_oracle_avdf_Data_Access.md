Vendor: Oracle
==============
### Product: [AVDF](../ds_oracle_avdf.md)
### Use-Case: [Data Access](../../../../UseCases/uc_data_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  11   |   5    |     2      |      2      |    2    |

| Event Type       | Rules    | Models    |
| ---- | ---- | ---- |
| database-login   | <b>T1213 - Data from Information Repositories</b><br> ↳ <b>DB-DbU-F</b>: First access to database for user<br> ↳ <b>DB-DbU-A</b>: Abnormal access to database for user<br> ↳ <b>DB-DbG-F</b>: First access to database for peer group<br> ↳ <b>DB-DbG-A</b>: Abnormal access to database for peer group<br> ↳ <b>DB-UDbZ-F</b>: First database activity from source zone per user, database<br> ↳ <b>DB-UDbZ-A</b>: Abnormal database activity from source zone per user, database<br> ↳ <b>DB-UDbH-F</b>: First database activity from host per user, database<br> ↳ <b>DB-UDbH-A</b>: Abnormal database activity from host per user, database<br> ↳ <b>DB-UDbI-F</b>: First database activity from IP per user, database<br> ↳ <b>DB-UDbI-A</b>: Abnormal database activity from IP per user, database |  • <b>DB-UDbI</b>: Database activity from source IP per user, database<br> • <b>DB-UDbH</b>: Database activity from host per user, database<br> • <b>DB-UDbZ</b>: Database activity from source zone per user, database<br> • <b>DB-DbG</b>: Peer groups per database<br> • <b>DB-DbU</b>: Users per database |
| failed-app-login | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-F-FL</b>: Failed login to application    |    |