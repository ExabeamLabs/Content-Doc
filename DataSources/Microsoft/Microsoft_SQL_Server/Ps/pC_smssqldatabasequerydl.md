#### Parser Content
```Java
{
Name = s-mssql-database-query-dl
  DataType = "database-query"
  Conditions = [ """EventCode=33205""", """action_id:DL""" ]

s-mssql-database-query = {
      Vendor = Microsoft
      Product = Microsoft SQL Server
      Lms = Splunk
      DataType = "database-query"
      IsHVF = true
      TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
      Fields = [
        """\WComputerName =({host}[^=\s]{1,2000})""",
        """\WEventCode=({event_code}\d{1,100})""",
        """\WSourceName =({service_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
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
    }

cef-ad-fs-audit = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  TimeFormat = "epoch"
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sexternalId=({event_code}\d{1,100})""",
    """\sdhost=({dest_host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\sahost=({src_host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sdvc=({host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\sdvchost=({host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\sdeviceSeverity=({outcome}\w+)""",
    """\scs5=({user_email}[^@=\s]{1,2000}@[^@=\s\-]{1,2000})""",
    """\scs5=({domain}[^\\=]{1,2000})\\+({user}[^\\=]{1,2000}?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\sduser=(NETWORK SERVICE|({user}.+?))(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """CEF:([^\|]{0,2000}\|){5}({failure_reason}[^\|]{1,2000}).*Audit_failure""",
    """Audit_failure.*\scs5=[^=\-]{0,2000}?-(|({failure_reason}.+?))(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
  
}
```