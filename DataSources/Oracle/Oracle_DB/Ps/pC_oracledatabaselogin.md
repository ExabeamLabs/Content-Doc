#### Parser Content
```Java
{
Name = oracle-database-login
  DataType = "database-login"
  Conditions = [ """action_name":"LOGON""", """os_username""", """userhost""", """priv_used""", """db_name""", """extended_timestamp""" ]

oracle-database-event = {
    Vendor = Oracle
    Product = Oracle DB
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)"""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """"userhost":"(([^\\]{1,2000})[\\]{1,2000})?({src_host}[^"]{1,2000})"""",
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