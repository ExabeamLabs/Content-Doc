#### Parser Content
```Java
{
Name = s-mssql-database-login
  DataType = "database-login"
  Conditions = [ """EventCode=33205""", """action_id:LGIS""" ]

s-mssql-database-login = {
      Vendor = Microsoft
      Product = SQL Server
      Lms = Splunk
      DataType = "database-login"
      IsHVF = true
      TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
      Fields = [
        """exabeam_host=({host}[\w.\-]{1,2000})""",
        """\WComputerName =({host}[^=\s]{1,2000})""",
        """\WEventCode=({event_code}\d{1,100})""",
        """\WSourceName =({service_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wsucceeded:({outcome}[^:\s]{1,2000})""",
        """\Wevent_time:({time}\d{1,100}\-\d{1,100}\-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}\.\d{3})""",
        """\WUser=({user}[^\s]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\WSid=({user_sid}[^\s]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wserver_principal_name:(({domain}[^\\\/]{1,2000}?)[\\\/])?({db_user}[^\\\/\s]{1,2000}?)(\s{1,100}\w+:|\s{0,100}$)""",
        """\Wserver_principal_sid:({db_user_sid}[^\s]{1,2000})""",
        """\Wserver_instance_name:({dest_host}[^\s]{1,2000})""",
        """\Wadditional_information:.*?<address>({src_ip}[a-fA-F\d.:]{1,2000})""",
        """\Wdatabase_name:({database_name}[^\s]{1,2000})""",
      ]
    }
    
    s-mssql-database-query = {
      Vendor = Microsoft
      Product = SQL Server
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

    s-mssql-database-query-1 = {
      Vendor = Microsoft
      Product = SQL Server
      Lms = Splunk
      TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSS" 
      Fields = [
        """sql.server_instance_name=({host}[\w.-]{1,2000})""",
        """\.sql\.action_id="{1,20}({db_operation}\w{1,2000})\s{0,100}"""",
        """\.sql\.event_time="{1,20}({time}\d{4}-\d{2}-\d{2} (\d{2}:){2}\d{2}\.\d{7})"{1,20}""",
        """\.server_principal_name="{0,20}(({domain}[^\\]{1,2000}?)[\\]{1,2})?({db_user}[^\s]{1,2000}?)"{0,20}(\s{1,100}\.sql\.)""",
        """\.sql\.database_name=({database_name}[^=]{1,2000}?)\s{1,100}\.sql""",
        """\.sql\.schema_name=({database_schema}[^=]{1,2000}?)\s{1,100}\.sql""",
        """\.sql\.object_name=({database_object}[^=]{1,2000}?)\s{1,100}\.sql\.\w+=""",
        """sql\.statement="{1,20}({db_query}[^"]{1,2000})"{1,20}\s{1,100}.sql"""
      ]
      DupFields = [ "db_user->user" ]
    }

cef-ad-fs-audit = {
  Vendor = Microsoft
  Product = Windows
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