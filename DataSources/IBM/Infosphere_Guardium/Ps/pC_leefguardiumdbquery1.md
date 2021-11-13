#### Parser Content
```Java
{
Name = leef-guardium-db-query-1
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = Syslog
  DataType = "database-query"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """LEEF:""", """|IBM|Guardium|""", """|type=""", """|serverType=""" ]
  Fields = [
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) guard_sender""",
    """\|devTime=({time}\d\d\d\d-\d{1,100}-\d{1,100} \d\d:\d\d:\d\d)""",
    """\|ruleDesc=({rule_description}[^\|]{1,2000})""",
    """\|serverType=({server_type}[^\|]{1,2000})""",
    """\|dbUser=(({domain}[^\|\\]{1,2000})\\)?({db_user}[^\|\\]{1,2000})""",
    """\|usrName =(|({user}[^\|]{1,2000}))""",
    """\|sourceProgram=({source_program}[^\|]{1,2000})""",
    """\|dst=({dest_ip}[a-fA-F\d:.]{1,2000})""",
    """\|dstPort=({dest_port}\d{1,100})""",
    """\|src=({src_ip}[a-fA-F\d:.]{1,2000})""",
    """\|srcPort=({src_port}\d{1,100})""",
    """\|sql=\s{0,20}({db_operation}[^\|]{1,2000}?)\s{0,20}\|""",
    """\|protocol=({protocol}[^\|]{1,2000})""",
    """\|usrName =({service_name}[^;\|]{1,2000}?)\s{0,20}(;|\|)"""
  ]
  DupFields = [ "db_user->account" ]


}
```