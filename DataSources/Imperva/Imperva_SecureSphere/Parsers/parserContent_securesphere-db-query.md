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
    """exabeam_host=({host}[\w\-.]+)""",
    """\WsrcPort=({src_port}\d{1,100})""",
    """\WsrcIP=({src_ip}[a-fA-F:\d\.]+)""",
    """\WdstPort=({dest_port}\d{1,100})""",
    """\WdstIP=({dest_ip}[a-fA-F:\d\.]+)""",
    """\WcreatTime=({time}\d{1,100} \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """\WsrvGroup=(|({server_group}[^,]+)),""",
    """\Wservice=(|({service_name}.+?))(,\w+=|\s{0,100}$)""",
    """\WappName=(|({app}[^,]+)),""",
    """\WdbUsername=(?:Hashed User \(Unsupported SSL cipher\)|(({domain}[^\\,]+)\\)?({db_user}[^,\\]+?))(,\w+=|\s{0,100}$)""",
    """\WdbName=(|({database_name}.+?))(,\w+=|\s{0,100}$)""",
    """\WrespSize=({response_size}\d{1,100})""",
    """\Waction=".*?({db_operation}(?i)(insert|delete|truncate|drop|alter|create|update|enable|disable|merge|delete|merge|select|dbcc))""",
    """\WrawQuery="(|({db_query}[^"]+))""""
    """\WeventType=(|({log_type}[^,]+)),""",
    """\WosUsername=(|({os_user}[^,]+)),""",
    """\WsrcHost=(|({src_host}[^,]+)),""",
    """\WsqlError=(|({sql_error}[^,]+)),""",
    """\WrespTime=(|({response_time}[^,]+)),""",
    """\WschemaName=(|({database_schema}[^,]+)),""",
  ]
  DupFields = [ "db_user->account", "os_user->user" ]
}
```