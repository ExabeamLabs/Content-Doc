#### Parser Content
```Java
{
Name = s-mssql-database-query-sl-1
  DataType = "database-query"
  Conditions = [ """.sql.class_type=""", """.sql.statement=""", """.sql.database_name""", """.sql.action_id="SL""" ]

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