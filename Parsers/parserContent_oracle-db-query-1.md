#### Parser Content
```Java
{
Name = oracle-db-query-1
  Vendor = Oracle
  Lms = Direct
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"os_username""", """"dbid""", """"sql_text""", """"GRANT ROLE""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"dbid\\"+:\\"+({database_id}[^"\\]+)""",
    """"sql_text\\"+:\\"+({db_query}[^"\\]+)""",
    """HOST=({src_ip}[a-fA-F\d.:]+)""",
    """"userhost\\"+:\\"+({src_host}[^"\\]+)""",
    """"terminal\\"+:\\"+({terminal}[^"\\]+)""",
    """"timestamp\\"+:\\"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"username\\"+:\\"+({db_user}[^"\\]+)""",
    """"os_username\\"+:\\"+({os_user}[^"\\]+)"""
  ]
  DupFields = [ "database_id->database_name", "os_user->user", "db_user->account" ]
}
```