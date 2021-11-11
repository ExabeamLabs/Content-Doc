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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """\d\d:\d\d:\d\d ({host}\S{1,2000}) CEF:""",
    """\WcreateTime="({time}\w{3} \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsrc=(0.0.0.0|({src_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\WOperationType="table"[^=]{1,100}object="(|({table_name}[^"]{1,2000}))"""",
    """\Wobject="(|({table_name}[^"]{1,2000}))[^"]{1,100}OperationType="table"""",
    """\WdbUsername="(|({domain}[^"\\]{1,2000})\\)?(|({db_user}[^"\\]{1,2000}))"""",
    """\WserviceName ="(|({service_name}[^"]{1,2000}))"""",
    """\WappName ="(|({app}[^"]{1,2000}))"""",
    """\WosUser="(|({user}[^"]{1,2000}))"""",
    """\WsrcHost="(|({domain}[^"\\]{1,2000})\\)?(|({src_host}[^"\\]{1,2000}))"""",
    """\WdatabaseName ="(|({database_name}[^"]{1,2000}))"""",
    """\WresponseSize=({response_size}\d{1,100})""",
    """\Woperation="(|(?i)(Logout)|({db_operation}[^"]{1,2000}))"""",
    """\WschemaName ="(|({schema}[^"]{1,2000}))"""",
    """\WparsedQuery="(|(N\/A \(logout\))|({db_query}[^\n]{1,2000})?)"\s{0,10}$""" 
  ]
  DupFields = [ "db_user->account" ]
}
}
```