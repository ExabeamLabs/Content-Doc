#### Parser Content
```Java
{
Name = s-mssql-database-query-al-xml
  Lms = Direct
  DataType = "database-query"
  Conditions = [ """>33205</EventID>""", """action_id:AL""" ]
  Fields = ${MicrosoftParserTemplates.s-mssql-database-query.Fields} [
    """\sserver_principal_name:({domain}[^\s]+)""",
    """\sserver_principal_name:(({domain}[^\\]+)\\)?({user}[^\s]+)\sserver_principal_sid""",
    """\sserver_principal_sid:({db_user_sid}[^\s]+)""",
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
        """\WComputerName=({host}[^=\s]+)""",
        """\WEventCode=({event_code}\d+)""",
        """\WSourceName=({service_name}.+?)(\s+\w+=|\s*$)""",
        """\Waction_id:({db_operation}[^\s]+)""",
        """\Wsucceeded:({outcome}[^:\s]+)""",
        """\Wevent_time:({time}\d+\-\d+\-\d+ \d+:\d+:\d+\.\d{3})""",
        """\WUser=({user}[^\s]+?)(\s+\w+=|\s*$)""",
        """\WSid=({user_sid}[^\s]+?)(\s+\w+=|\s*$)""",
        """\Wserver_principal_name:(({domain}[^\\\/]+?)[\\\/])?({db_user}[^\\\/\s]+?)(\s+\w+:|\s*$)""",
        """\Wserver_principal_sid:({db_user_sid}[^\s]+)""",
        """\Wserver_instance_name:({dest_host}[^\s]+)""",
        """\Wadditional_information:.*?<address>({src_ip}[a-fA-F\d.:]+)""",
        """\Wdatabase_name:({database_name}[^\s]+)""",
        """\Wschema_name:({schema_name}[^\s]+)""",
        """\Wobject_name:({table_name}[^\s]+)""",
        """\Wstatement:(|({db_query}.+?))(\s+\w+:|\s*$)"""
      ]

```