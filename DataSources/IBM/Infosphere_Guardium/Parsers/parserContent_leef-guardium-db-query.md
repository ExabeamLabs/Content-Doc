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
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) GuardiumSniffer\[\d{1,100}\]""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) guard_sender""",
    """\WruleDesc=({rule_description}[^\|]{1,2000})""",
    """\WdevTime=({time}\d\d\d\d-\d{1,100}-\d{1,100} \d\d:\d\d:\d\d)""",
    """\WserverType=({server_type}[^\|]{1,2000})""",
    """\WdbUser=(({domain}[^\|\\]{1,2000})\\)?({db_user}[^\|\\]{1,2000})""",
    """\WusrName=(|({user}[^\|]{1,2000}))""",
    """\WsourceProgram=({source_program}[^\|]{1,2000})""",
    """\Wdst=({dest_ip}[^\|]{1,2000})""",
    """\WdstPort=({dest_port}\d{1,100})""",
    """\WdbName=({database_name}[^\|]{1,2000})""",
    """\Wsrc=({src_ip}[^\|]{1,2000})""",
    """\WsrcPort=({src_port}\d{1,100})""",
    """\Wsql=\s{0,20}({db_operation}[^\|]{1,2000}?)\s{0,20}\|""",
    """\WSQLID=({additional_info}[^;\|]{1,2000}?)\s{0,100}(;|\|)""",
    """\WPROG=({app}[^;\|]{1,2000}?)\s{0,100}(;|\|)""",
    """\WDB_NAME=({database_name}[^;\|]{1,2000}?)\s{0,100}(;|\|)""",
    """\WusrName=({service_name}[^;\|]{1,2000}?)\s{0,100}(;|\|)""",
    """\Wprotocol=({protocol}[^\|]{1,2000})""",
  ]
  DupFields = [ "db_user->account" ]
}
```