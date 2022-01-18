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
    """({host}[\w\-.]{1,2000})\s{1,100}Oracle Audit""",
    """SESSIONID:\[\d{1,100}\]\s{0,100}"{1,20}({session_id}[^":]{1,2000})""",
    """USERID:\[\d{1,100}\]\s{0,100}"{1,20}({db_user}[^":]{1,2000})""",
    """USERHOST:\[\d{1,100}\]\s{0,100}"{1,20}({src_host}[^":]{1,2000})""",
    """RETURNCODE:\[\d{1,100}\]\s{0,100}"{1,20}({outcome}[^":]{1,2000})""",
    """OBJ\$+NAME:\[\d{1,100}\]\s{0,100}"{1,20}({database_name}[^":]{1,2000})""",
    """OS\$+USERID:\[\d{1,100}\]\s{0,100}"{1,20}({user}[^":]{1,2000})""",
    """DBID:\[\d{1,100}\]\s{0,100}"{1,20}({database_id}[^":]{1,2000})""",
    """COMMENT\$+TEXT:\[\d{1,100}\]\s{0,100}.+?PROTOCOL=({protocol}\w+)""",
    """COMMENT\$+TEXT:\[\d{1,100}\]\s{0,100}.+?HOST=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """COMMENT\$+TEXT:\[\d{1,100}\]\s{0,100}.+?PORT=({dest_port}\d{1,100})""",
  ]
  DupFields = [ "user->os_user" ]


}
```