#### Parser Content
```Java
{
Name = leef-guardium-db-query
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = QRadar
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """LEEF:""", """|IBM|Guardium|""", """|type=SQL_""" ]
  Fields = [
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) GuardiumSniffer\[\d+\]""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) guard_sender""",
    """\WruleDesc=({rule_description}[^\|]+)""",
    """\WdevTime=({time}\d\d\d\d-\d+-\d+ \d\d:\d\d:\d\d)""",
    """\WserverType=({server_type}[^\|]+)""",
    """\WdbUser=(({domain}[^\|\\]+)\\)?({db_user}[^\|\\]+)""",
    """\WusrName=(|({user}[^\|]+))""",
    """\WsourceProgram=({source_program}[^\|]+)""",
    """\Wdst=({dest_ip}[^\|]+)""",
    """\WdstPort=({dest_port}\d+)""",
    """\WdbName=({database_name}[^\|]+)""",
    """\Wsrc=({src_ip}[^\|]+)""",
    """\WsrcPort=({src_port}\d+)""",
    """\Wsql=({db_operation}[^\|]+)""",
    """\WSQLID=({additional_info}[^;\|]+?)\s*(;|\|)""",
    """\WPROG=({app}[^;\|]+?)\s*(;|\|)""",
    """\WDB_NAME=({database_name}[^;\|]+?)\s*(;|\|)""",
    """\WusrName=({service_name}[^;\|]+?)\s*(;|\|)""",
    """\Wprotocol=({protocol}[^\|]+)""",
  ]
  DupFields = [ "db_user->account" ]
}
```