#### Parser Content
```Java
{
Name = oracle-db-update
  Vendor = Oracle
  Product = Oracle Database
  Lms = Direct
  DataType = "database-update"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"action_name":"UPDATE"""", """"object_schema":"""", """"return_code":"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"event_timestamp":"({time}[^"]{1,2000})""",
    """"action_name":"({db_operation}[^"]{1,2000})""",
    """"return_code":"({return_code}[^"]{1,2000})""",
    """"os_username":"({user}[^"]{1,2000})""",
    """"dbusername":"({db_user}[^"]{1,2000})""",
    """IP_ADDRESS=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"userhost":"({src_host}[^"]{1,2000})""",
    """"object_schema":"({schema}[^"]{1,2000})""",
    """"object_name":"({database_object}[^"]{1,2000})""",
  ]
  DupFields = [ "db_user->account", "schema->database_name" ]


}
```