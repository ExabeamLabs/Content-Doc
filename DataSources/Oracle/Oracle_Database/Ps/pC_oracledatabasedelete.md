#### Parser Content
```Java
{
Name = oracle-database-delete
  DataType = "database-delete"
  Conditions = [ """"action_name":"SESSION REC"""", """"ses_actions":"---S------------"""", """"exa_jdbc_type":""", """"Oracle"""" ]
  Fields = ${OracleParsersTemplates.oracle-database-event.Fields}[
    """"exa_jdbc_hostname":"({dest_host}[^"]{1,2000})"""",
    """"exa_jdbc_database":"({database_name}[^"]{1,2000})"""",
    """({db_operation}---S------------)""",
    """({event_name}SESSION REC)""",
    """"obj_name":"({database_object}[^"]{1,2000})"""",
    """"exa_jdbc_type":"({app}[^"]{1,2000})"""",
    """"exa_jdbc_port":"({dest_port}\d{1,100})"""",
    """"returncode":"({return_code}[^"]{1,2000})"""",
    """"terminal":"({terminal}[^"]{1,2000})""""
  ]
  DupFields = [ "user->os_user", "db_user->account" ]

oracle-database-event = {
    Vendor = Oracle
    Product = Oracle Database
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)"""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """"userhost":"(({domain}[^\\"]{1,2000})[\\]{1,20})?({src_host}[^"]{1,2000})"""",
      """"os_username":"({user}[^"]{1,2000})"""",
      """"username":"({db_user}[^"]{1,2000})"""",
      """"db_name":"({database_name}[^"]{1,2000})"""",
      """"action_name":"({db_operation}[^"]{1,2000})"""",
      """"sessionid":"({session_id}[^"]{1,2000})"""",
      """"priv_used":"({additional_info}[^"]{1,2000})"""",
    ]
    DupFields = [ "db_operation->activity" 
}
```