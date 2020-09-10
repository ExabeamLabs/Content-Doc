#### Parser Content
```Java
{
Name = oracle-db-login
  Vendor = Oracle
  Product = Oracle DB
  Lms = Direct
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"os_username""", """"dbid""", """"LOGON""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"dbid\\"+:\\"+({database_id}[^"\\]+)""",
    """HOST=({src_ip}[a-fA-F\d.:]+)""",
    """"userhost\\"+:\\"+({src_host}[^"\\]+)""",
    """"terminal\\"+:\\"+({terminal}[^"\\]+)""",
    """"timestamp\\"+:\\"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"username\\"+:\\"+({db_user}[^"\\]+)""",
    """"os_username\\"+:\\"+({os_user}[^"\\]+)""",
    """PROTOCOL=({protocol}\w+)""",
    """"returncode\\"+:\\"+({return_code}[^"\\]+)"""
  ]
  DupFields = [ "database_id->database_name", "os_user->user", "db_user->account" ]
}
```