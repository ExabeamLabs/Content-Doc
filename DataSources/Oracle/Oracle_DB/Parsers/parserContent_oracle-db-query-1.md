#### Parser Content
```Java
{
Name = oracle-db-query-1
  Vendor = Oracle
  Product = Oracle DB
  Lms = Direct
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"os_username""", """"dbid""", """"sql_text""", """"GRANT ROLE""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"dbid\\"{1,20}:\\"{1,20}({database_id}[^"\\]+)""",
    """"sql_text\\"{1,20}:\\"{1,20}({db_query}[^"\\]+)""",
    """HOST=({src_ip}[a-fA-F\d.:]+)""",
    """"userhost\\"{1,20}:\\"{1,20}({src_host}[^"\\]+)""",
    """"terminal\\"{1,20}:\\"{1,20}({terminal}[^"\\]+)""",
    """"timestamp\\"{1,20}:\\"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"username\\"{1,20}:\\"{1,20}({db_user}[^"\\]+)""",
    """"os_username\\"{1,20}:\\"{1,20}({os_user}[^"\\]+)""",
    """"action_name\\"{1,20}:\\"{1,20}({db_operation}[^"\\]+)""", 
  ]
  DupFields = [ "database_id->database_name", "os_user->user", "db_user->account" ]
}
```