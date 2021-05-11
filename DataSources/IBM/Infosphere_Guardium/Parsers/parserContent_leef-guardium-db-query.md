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
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) GuardiumSniffer\[\d{1,100}\]""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) guard_sender""",
    """\WruleDesc=({rule_description}[^\|]+)""",
    """\WdevTime=({time}\d\d\d\d-\d{1,100}-\d{1,100} \d\d:\d\d:\d\d)""",
    """\WserverType=({server_type}[^\|]+)""",
    """\WdbUser=(({domain}[^\|\\]+)\\)?({db_user}[^\|\\]+)""",
    """\WusrName=(|({user}[^\|]+))""",
    """\WsourceProgram=({source_program}[^\|]+)""",
    """\Wdst=({dest_ip}[^\|]+)""",
    """\WdstPort=({dest_port}\d{1,100})""",
    """\WdbName=({database_name}[^\|]+)""",
    """\Wsrc=({src_ip}[^\|]+)""",
    """\WsrcPort=({src_port}\d{1,100})""",
    """\Wsql=\s{0,20}({db_operation}[^\|]+?)\s{0,20}\|""",
    """\WSQLID=({additional_info}[^;\|]+?)\s{0,100}(;|\|)""",
    """\WPROG=({app}[^;\|]+?)\s{0,100}(;|\|)""",
    """\WDB_NAME=({database_name}[^;\|]+?)\s{0,100}(;|\|)""",
    """\WusrName=({service_name}[^;\|]+?)\s{0,100}(;|\|)""",
    """\Wprotocol=({protocol}[^\|]+)""",
  ]
  DupFields = [ "db_user->account" ]
}
```