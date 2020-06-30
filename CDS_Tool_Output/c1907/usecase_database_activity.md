Use Case: Database Activity
===========================

### Supported Data Sources

_The following list of Supported Exabeam Data Sources power this use case:_

* [Imperva CounterBreach](datasource_counterbreach_imperva_counterbreach.md)
* [IBM Infosphere Guardium](datasource_ibm_infosphere_guardium_ibm_infosphere_guardium.md)
* [McAfee MDAM](datasource_mdam_mcafee_mdam.md)
* [MariaDB](datasource_mariadb_mariadb.md)
* [Microsoft Azure EventHub](datasource_microsoft_azure_eventhub_microsoft_azure_eventhub.md)
* [Microsoft Azure](datasource_microsoft_azure_microsoft_azure.md)
* [Microsoft SQL Server](datasource_microsoft_sql_server_microsoft_sql_server.md)
* [Mysql](datasource_mysql_mysql.md)
* [Oracle](datasource_oracle_database_oracle.md)
* [PostgreSQL DB](datasource_postgresql_db_postgresql_db.md)
* [PostgreSQL](datasource_postgresql_postgresql.md)
* [RangerAudit](datasource_rangeraudit_rangeraudit.md)
* [Microsoft](datasource_sql_server_microsoft.md)
* [Imperva SecureSphere](datasource_securesphere_imperva_securesphere.md)
* [Oracle](datasource_siebel_crm_oracle.md)
* [Sybase](datasource_sybase_sybase.md)
* [Teradata RDBMS](datasource_teradata_rdbms_teradata_rdbms.md)
* [jSONAR SonarG](datasource_jsonar_sonarg_jsonar_sonarg.md)


### Exabeam Event Types

- 
- database-alert
- database-login
- database-query
- sequence-end
### Exabeam Content Library for this Use Case


_Rules_
- DB-FL-COUNT : Abnormal number of failed database logins for user
- DB-GN-ALERT-A : Abnormal database alert name in the peer group
- DB-GN-ALERT-F : First database alert name in the peer group
- DB-OG-ALERT-A : Abnormal peer group triggering database alert in the organization
- DB-OG-ALERT-F : First database alert triggered for peer group in the organization
- DB-ON-ALERT-A : Abnormal database alert name in the organization
- DB-ON-ALERT-F : First database alert name in the organization
- DB-OPCOUNT : Abnormal number of database operations
- DB-OU-ALERT-A : Abnormal user triggering database alert in the organization
- DB-OU-ALERT-F : First database alert triggered for this user in the organization
- DB-TEMP-DIRECTORY-A : Abnormal process has been executed from a temporary directory by this user during database activity
- DB-TEMP-DIRECTORY-F : First time process has been executed from a temporary directory by this user during database activity
- DB-UN-ALERT-A : Abnormal database alert name for user
- DB-UN-ALERT-F : First database alert name for user
- G-A : Abnormal access to database for peer group
- G-F : First access to database for peer group
- H-A : Abnormal database activity from host per user, database
- H-F : First database activity from host per user, database
- I-A : Abnormal database activity from IP per user, database
- I-F : First database activity from IP per user, database
- O-A : Abnormal database operation for peer group, database
- O-A : Abnormal database operation for user, database
- O-F : First database operation for peer group, database
- O-F : First database operation for user, database
- QL-A : Abnormal database query length
- U-A : Abnormal access to database for user
- U-F : First access to database for user
- Z-A : Abnormal database activity from source zone per user, database
- Z-F : First database activity from source zone per user, database
- ZO-A : Abnormal database operation from source zone for database
- ZO-F : First database operation from source zone for database


_Exabeam Models_
- DB-DbG : 
- DB-DbU : 
- DB-DbZO : 
- DB-FL-COUNT : 
- DB-GDbO : 
- DB-GN-ALERT : 
- DB-OG-ALERT : 
- DB-ON-ALERT : Database alert names triggered in the organization
- DB-OPCOUNT : 
- DB-OU-ALERT : 
- DB-UDbH : 
- DB-UDbI : 
- DB-UDbO : 
- DB-UDbQL : 
- DB-UDbZ : 
- DB-UN-ALERT : Database alert names for user
- DB-UP-TEMP : 
