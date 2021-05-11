#### Parser Content
```Java
{
Name = leef-guardium-db-failed-login
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = QRadar
  DataType = "database-failed-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """LEEF:""", """|IBM|Guardium|""", """|type=LOGIN_FAILED|""" ]
  Fields = [
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) GuardiumSniffer\[\d{1,100}\]""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) guard_sender""",
    """\WruleDesc=({rule_description}[^\|]+)""",
    """\WdevTime=({time}\d\d\d\d-\d{1,100}-\d{1,100} \d\d:\d\d:\d\d)""",
    """\WserverType=({server_type}[^\|]+)""",
    """\WdbUser=(({domain}[^\|\\]+)\\)?(\?|({db_user}[^\|\\]+))""",
    """\WusrName=(|({user}[^\|]+))""",
    """\WsourceProgram=({source_program}[^\|]+)""",
    """\Wdst=({dest_ip}[^\|]+)""",
    """\WdstPort=({dest_port}\d{1,100})""",
    """\WdbName=(|({database_name}[^\|]+))""",
    """\Wsrc=({src_ip}[^\|]+)""",
    """\WsrcPort=({src_port}\d{1,100})""",
    """\Werror=({reason}[^\|]+?)("|\s{0,20}$)"""
  ]
  DupFields = [ "db_user->account" ]
}
```