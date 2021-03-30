#### Parser Content
```Java
{
Name = oracle-db-query
  Vendor = Oracle
  Product = Oracle DB
  Lms = Direct
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"action_name":"""", """"object_schema":"""", """"return_code":"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"event_timestamp":"({time}[^"]+)""",
    """"action_name":"({db_operation}[^"]+)""",
    """"sql_text":"({db_query}.*?)","""",
    """"return_code":"({return_code}[^"]+)""",
    """"os_username":"({user}[^"]+)""",
    """"dbusername":"({db_user}[^"]+)""",
    """IP_ADDRESS=({src_ip}[A-Fa-f:\d.]+)""",
    """"userhost":"({src_host}[^"]+)""",
    """"terminal":"({app}[^"]+)""",
    """"object_schema":"({schema}[^"]+)""",
    """"object_name":"({database_object}[^"]+)""",
  ]
  DupFields = [ "db_user->account", "schema->database_name" ]
}
```