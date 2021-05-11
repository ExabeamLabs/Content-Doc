#### Parser Content
```Java
{
Name = s-mssql-database-login-failed
  DataType = "database-failed-login"
  Conditions = [ """EventCode=33205""", """action_id:LGIF""" ]
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
        """exabeam_host=({host}[\w.\-]+)""",
        """\WComputerName=({host}[^=\s]+)""",
        """\WEventCode=({event_code}\d{1,100})""",
        """\WSourceName=({service_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wsucceeded:({outcome}[^:\s]+)""",
        """\Wevent_time:({time}\d{1,100}\-\d{1,100}\-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}\.\d{3})""",
        """\WUser=({user}[^\s]+?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\WSid=({user_sid}[^\s]+?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wserver_principal_name:(({domain}[^\\\/]+?)[\\\/])?({db_user}[^\\\/\s]+?)(\s{1,100}\w+:|\s{0,100}$)""",
        """\Wserver_principal_sid:({db_user_sid}[^\s]+)""",
        """\Wserver_instance_name:({dest_host}[^\s]+)""",
        """\Wadditional_information:.*?<address>({src_ip}[a-fA-F\d.:]+)""",
        """\Wdatabase_name:({database_name}[^\s]+)""",
      ]

```