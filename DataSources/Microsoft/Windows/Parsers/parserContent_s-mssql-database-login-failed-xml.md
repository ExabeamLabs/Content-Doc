#### Parser Content
```Java
{
Name = s-mssql-database-login-failed-xml
  Lms = Direct
  DataType = "database-failed-login"
  Conditions = [ """>33205</EventID>""", """action_id:LGIF""" ]
  Fields = ${MicrosoftParserTemplates.s-mssql-database-login.Fields} [
    """\Wstatement:({failure_reason}[^.]+)"""
  ]
}
s-mssql-database-login = {
      Vendor = Microsoft
      Product = Microsoft SQL Server
      Lms = Splunk
      DataType = "database-login"
      IsHVF = true
      TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
      Fields = [
        """\WComputerName=({host}[^=\s]+)""",
        """\WEventCode=({event_code}\d+)""",
        """\WSourceName=({service_name}.+?)(\s+\w+=|\s*$)""",
        """\Wsucceeded:({outcome}[^:\s]+)""",
        """\Wevent_time:({time}\d+\-\d+\-\d+ \d+:\d+:\d+\.\d{3})""",
        """\WUser=({user}[^\s]+?)(\s+\w+=|\s*$)""",
        """\WSid=({user_sid}[^\s]+?)(\s+\w+=|\s*$)""",
        """\Wserver_principal_name:(({domain}[^\\\/]+?)[\\\/])?({db_user}[^\\\/\s]+?)(\s+\w+:|\s*$)""",
        """\Wserver_principal_sid:({db_user_sid}[^\s]+)""",
        """\Wserver_instance_name:({dest_host}[^\s]+)""",
        """\Wadditional_information:.*?<address>({src_ip}[a-fA-F\d.:]+)""",
        """\Wdatabase_name:({database_name}[^\s]+)""",
      ]

```