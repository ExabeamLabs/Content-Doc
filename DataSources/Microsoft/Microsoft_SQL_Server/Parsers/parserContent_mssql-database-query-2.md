#### Parser Content
```Java
{
Name = mssql-database-query-2
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = Splunk
  DataType = "database-query"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSS"
  Conditions = [ """server_instance_name""", """exa_jdbc_type""", """SQL Server""", """database_name""" ]
  Fields = [
    """exabeam_host=([^=@]+@\s*)?({host}\S+)""", 
    """"+event_time"+:"+({time}[^"]+)""",
    """"+server_principal_name"+:"+(({domain}[^\\"]+?)\\+({user}[^"]+)|({db_user}[^"]+))""",
    """"+server_instance_name"+:"+({dest_host}[^"]+)""",
    """"+statement"+:"+({db_query}.+?)\s*"+""",
    """"+server_principal_sid"+:"+\s*({db_user_sid}.+?)\s*"+""",
    """"+action_id"+:"+({db_operation}.+?)\s*"+"""
    """"+database_name"+:"+({database_name}[^"]+)"+,""",
    """"+schema_name"+:"+({schema_name}[^"]+)"+,""",
    """"+object_name"+:"+({table_name}[^"]+)"+,""",
    """"+succeeded"+:"?({outcome}[^\s,]+)""",
    ]
}
```