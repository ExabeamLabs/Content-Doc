#### Parser Content
```Java
{
Name = oracle-db-login-1
  Vendor = Oracle
  Product = Oracle DB
  Lms = Syslog
  DataType = "database-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Oracle Audit""", """ACTION:""", """USERID:""", """LENGTH:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]+)\s{1,100}Oracle Audit""",
    """SESSIONID:\[\d{1,100}\]\s{0,100}"{1,20}({session_id}[^":]+)""",
    """USERID:\[\d{1,100}\]\s{0,100}"{1,20}({db_user}[^":]+)""",
    """USERHOST:\[\d{1,100}\]\s{0,100}"{1,20}({src_host}[^":]+)""",
    """RETURNCODE:\[\d{1,100}\]\s{0,100}"{1,20}({outcome}[^":]+)""",
    """OBJ\$+NAME:\[\d{1,100}\]\s{0,100}"{1,20}({database_name}[^":]+)""",
    """OS\$+USERID:\[\d{1,100}\]\s{0,100}"{1,20}({user}[^":]+)""",
    """DBID:\[\d{1,100}\]\s{0,100}"{1,20}({database_id}[^":]+)""",
    """COMMENT\$+TEXT:\[\d{1,100}\]\s{0,100}.+?PROTOCOL=({protocol}\w+)""",
    """COMMENT\$+TEXT:\[\d{1,100}\]\s{0,100}.+?HOST=({dest_ip}[a-fA-F\d.:]+)""",
    """COMMENT\$+TEXT:\[\d{1,100}\]\s{0,100}.+?PORT=({dest_port}\d{1,100})""",
  ]
  DupFields = [ "user->os_user" ]
}
```