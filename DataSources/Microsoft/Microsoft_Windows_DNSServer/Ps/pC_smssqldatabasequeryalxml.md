#### Parser Content
```Java
{
Name = s-mssql-database-query-al-xml
  Lms = Direct
  DataType = "database-query"
  Conditions = [ """>33205</EventID>""", """action_id:AL""" ]
  Fields = ${MicrosoftParserTemplates.s-mssql-database-query.Fields} [
    """\sserver_principal_name:({domain}[^\s]{1,2000})""",
    """\sserver_principal_name:(({domain}[^\\]{1,2000})\\)?({user}[^\s]{1,2000})\sserver_principal_sid""",
    """\sserver_principal_sid:({db_user_sid}[^\s]{1,2000})""",
  ]
}
s-mssql-database-query = {
      Vendor = Microsoft
      Product = Microsoft SQL Server
      Lms = Splunk
      DataType = "database-query"
      IsHVF = true
      TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
      Fields = [
        """\WComputerName=({host}[^=\s]{1,2000})""",
        """\WEventCode=({event_code}\d{1,100})""",
        """\WSourceName=({service_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\Waction_id:({db_operation}[^\s]{1,2000})""",
        """\Wsucceeded:({outcome}[^:\s]{1,2000})""",
        """\Wevent_time:({time}\d{1,100}\-\d{1,100}\-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}\.\d{3})""",
        """\WUser=({user}[^\s]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\WSid=({user_sid}[^\s]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wserver_principal_name:(({domain}[^\\\/]{1,2000}?)[\\\/])?({db_user}[^\\\/\s]{1,2000}?)(\s{1,100}\w+:|\s{0,100}$)""",
        """\Wserver_principal_sid:({db_user_sid}[^\s]{1,2000})""",
        """\Wserver_instance_name:({dest_host}[^\s]{1,2000})""",
        """\Wadditional_information:.*?<address>({src_ip}[a-fA-F\d.:]{1,2000})""",
        """\Wdatabase_name:({database_name}[^\s]{1,2000})""",
        """\Wschema_name:({schema_name}[^\s]{1,2000})""",
        """\Wobject_name:({table_name}[^\s]{1,2000})""",
        """\Wstatement:(|({db_query}.+?))(\s{1,100}\w+:|\s{0,100}$)"""
      ]

```