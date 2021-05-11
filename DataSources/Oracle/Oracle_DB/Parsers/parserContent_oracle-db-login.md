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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"dbid\\"{1,20}:\\"{1,20}({database_id}[^"\\]+)""",
    """HOST=({src_ip}[a-fA-F\d.:]+)""",
    """"userhost\\"{1,20}:\\"{1,20}({src_host}[^"\\]+)""",
    """"terminal\\"{1,20}:\\"{1,20}({terminal}[^"\\]+)""",
    """"timestamp\\"{1,20}:\\"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"username\\"{1,20}:\\"{1,20}({db_user}[^"\\]+)""",
    """"os_username\\"{1,20}:\\"{1,20}({os_user}[^"\\]+)""",
    """PROTOCOL=({protocol}\w+)""",
    """"returncode\\"{1,20}:\\"{1,20}({return_code}[^"\\]+)"""
  ]
  DupFields = [ "database_id->database_name", "os_user->user", "db_user->account" ]
}
```