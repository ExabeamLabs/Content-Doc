#### Parser Content
```Java
{
Name = oracle-db-query-2
  Vendor = Oracle
  Product = Oracle DB
  Lms = Direct
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"os_username""", """"dbid""", """"sql_text""", """"ALTER USER""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"dbid\\"{1,20}:\\"{1,20}({database_id}[^"\\]{1,2000})""",
    """"sql_text\\"{1,20}:\\"{1,20}({db_query}[^"\\]{1,2000})""",
    """HOST=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"userhost\\"{1,20}:\\"{1,20}({src_host}[^"\\]{1,2000})""",
    """"terminal\\"{1,20}:\\"{1,20}({terminal}[^"\\]{1,2000})""",
    """"timestamp\\"{1,20}:\\"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"username\\"{1,20}:\\"{1,20}({db_user}[^"\\]{1,2000})""",
    """"os_username\\"{1,20}:\\"{1,20}({os_user}[^"\\]{1,2000})"""
  ]
  DupFields = [ "database_id->database_name", "os_user->user", "db_user->account" ]
}
```