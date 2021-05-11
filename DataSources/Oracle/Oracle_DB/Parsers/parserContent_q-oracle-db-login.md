#### Parser Content
```Java
{
Name = q-oracle-db-login
  Vendor = Oracle
  Product = Oracle DB
  Lms = QRadar
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """ ACTION_NAME: """, """"LOGON"""", """ COMMENT_TEXT: """, """"Authenticated by:""" ]
  Fields = [
    """OS_USERNAME:\s{0,100}"{1,20}({os_user}[^":]+)""",
    """\sUSERNAME:\s{0,100}"{1,20}({db_user}[^":]+)""",
    """USERHOST:\s{0,100}"{1,20}({dest_host}[^":]+)""",
    """TIMESTAMP:\s{0,100}"{1,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """COMMENT_TEXT:\s{0,100}"{1,20}[^"]*?PROTOCOL=({protocol}\w+)""",
    """COMMENT_TEXT:\s{0,100}"{1,20}[^"]*?HOST=({dest_ip}[a-fA-F\d.:]+)""",
    """SESSIONID:\s{0,100}"{1,20}({session_id}[^":]+)""",
    """OS_PROCESS:\s{0,100}"{1,20}({process_id}\d{1,100})""",
    """DBID:\s{0,100}"{1,20}({database_name}\d{1,100})"""
  ]
  DupFields = [ "os_user->user", "db_user->account" ]
}
```