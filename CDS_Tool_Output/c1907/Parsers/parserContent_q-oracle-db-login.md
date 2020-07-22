#### Parser Content
```Java
{
Name = q-oracle-db-login
  Vendor = Oracle
  Lms = QRadar
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """ ACTION_NAME: """, """"LOGON"""", """ COMMENT_TEXT: """, """"Authenticated by:""" ]
  Fields = [
    """OS_USERNAME:\s*"+({os_user}[^":]+)""",
    """\sUSERNAME:\s*"+({db_user}[^":]+)""",
    """USERHOST:\s*"+({dest_host}[^":]+)""",
    """TIMESTAMP:\s*"+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)""",
    """COMMENT_TEXT:\s*"+[^"]*?PROTOCOL=({protocol}\w+)""",
    """COMMENT_TEXT:\s*"+[^"]*?HOST=({dest_ip}[a-fA-F\d.:]+)""",
    """SESSIONID:\s*"+({session_id}[^":]+)""",
    """OS_PROCESS:\s*"+({process_id}\d+)"""
  ]
  DupFields = [ "os_user->user", "db_user->account" ]
}
```