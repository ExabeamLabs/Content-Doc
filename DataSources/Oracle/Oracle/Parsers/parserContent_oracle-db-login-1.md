#### Parser Content
```Java
{
Name = oracle-db-login-1
  Vendor = Oracle
  Lms = Syslog
  DataType = "database-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Oracle Audit""", """ACTION:""", """USERID:""", """LENGTH:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]+)\s+Oracle Audit""",
    """SESSIONID:\[\d+\]\s*"+({session_id}[^":]+)""",
    """USERID:\[\d+\]\s*"+({db_user}[^":]+)""",
    """USERHOST:\[\d+\]\s*"+({src_host}[^":]+)""",
    """RETURNCODE:\[\d+\]\s*"+({outcome}[^":]+)""",
    """OBJ\$+NAME:\[\d+\]\s*"+({database_name}[^":]+)""",
    """OS\$+USERID:\[\d+\]\s*"+({user}[^":]+)""",
    """DBID:\[\d+\]\s*"+({database_id}[^":]+)""",
    """COMMENT\$+TEXT:\[\d+\]\s*.+?PROTOCOL=({protocol}\w+)""",
    """COMMENT\$+TEXT:\[\d+\]\s*.+?HOST=({dest_ip}[a-fA-F\d.:]+)""",
    """COMMENT\$+TEXT:\[\d+\]\s*.+?PORT=({dest_port}\d+)""",
  ]
  DupFields = [ "user->os_user" ]
}
```