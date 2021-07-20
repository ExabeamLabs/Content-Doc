#### Parser Content
```Java
{
Name = securesphere-db-query
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """IMPERVA-Imperva""", """,respSize=""", """,eventType=Query""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """\WsrcPort=({src_port}\d{1,100})""",
    """\WsrcIP=({src_ip}[a-fA-F:\d\.]{1,2000})""",
    """\WdstPort=({dest_port}\d{1,100})""",
    """\WdstIP=({dest_ip}[a-fA-F:\d\.]{1,2000})""",
    """\WcreatTime=({time}\d{1,100} \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """\WsrvGroup=(|({server_group}[^,]{1,2000})),""",
    """\Wservice=(|({service_name}.+?))(,\w+=|\s{0,100}$)""",
    """\WappName=(|({app}[^,]{1,2000})),""",
    """\WdbUsername=(?:Hashed User \(Unsupported SSL cipher\)|(({domain}[^\\,]{1,2000})\\)?({db_user}[^,\\]{1,2000}?))(,\w+=|\s{0,100}$)""",
    """\WdbName=(|({database_name}.+?))(,\w+=|\s{0,100}$)""",
    """\WrespSize=({response_size}\d{1,100})""",
    """\Waction=".*?({db_operation}(?i)(insert|delete|truncate|drop|alter|create|update|enable|disable|merge|delete|merge|select|dbcc))""",
    """\WrawQuery="(|({db_query}[^"]{1,2000}))""""
    """\WeventType=(|({log_type}[^,]{1,2000})),""",
    """\WosUsername=(|({os_user}[^,]{1,2000})),""",
    """\WsrcHost=(|({src_host}[^,]{1,2000})),""",
    """\WsqlError=(|({sql_error}[^,]{1,2000})),""",
    """\WrespTime=(|({response_time}[^,]{1,2000})),""",
    """\WschemaName=(|({database_schema}[^,]{1,2000})),""",
  ]
  DupFields = [ "db_user->account", "os_user->user" ]
}
```