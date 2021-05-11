#### Parser Content
```Java
{
Name = cef-securesphere-db-query-1
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Splunk
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|Imperva Inc.|SecureSphere|""", """responseSize=""", """bindVar="""" ]
  Fields = [
    """\d\d:\d\d:\d\d ({host}\S+) CEF:""",
    """\WcreateTime="({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\WOperationType="table".+?object="(|({table_name}[^"]+))"""",
    """\Wobject="(|({table_name}[^"]+)).+?OperationType="table"""",
    """\WdbUsername="(|({domain}[^"\\]+)\\)?(|({db_user}[^"\\]+))"""",
    """\WserviceName="(|({service_name}[^"]+))"""",
    """\WappName="(|({app}[^"]+))"""",
    """\WosUser="(|({user}[^"]+))"""",
    """\WsrcHost="(|({domain}[^"\\]+)\\)?(|({src_host}[^"\\]+))"""",
    """\WdatabaseName="(|({database_name}[^"]+))"""",
    """\WresponseSize=({response_size}\d{1,100})""",
    """\Woperation="(|({db_operation}[^"]+))"""",
    """\WschemaName="(|({schema}[^"]+))"""",
    """\WparsedQuery="(|({db_query}[^"]+))"""",
  ]
  DupFields = [ "db_user->account" ]
}
```