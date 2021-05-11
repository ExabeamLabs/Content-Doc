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
    """exabeam_host=([^=@]+@\s{0,100})?({host}\S+)""", 
    """"{1,20}event_time"{1,20}:"{1,20}({time}[^"]+)""",
    """"{1,20}server_principal_name"{1,20}:"{1,20}(({domain}[^\\"]+?)\\+({user}[^"]+)|({db_user}[^"]+))""",
    """"{1,20}server_instance_name"{1,20}:"{1,20}({dest_host}[^"]+)""",
    """"{1,20}statement"{1,20}:"{1,20}({db_query}.+?)\s{0,100}"{1,20}""",
    """"{1,20}server_principal_sid"{1,20}:"{1,20}\s{0,100}({db_user_sid}.+?)\s{0,100}"{1,20}""",
    """"{1,20}action_id"{1,20}:"{1,20}({db_operation}.+?)\s{0,100}"{1,20}"""
    """"{1,20}database_name"{1,20}:"{1,20}({database_name}[^"]+)"{1,20}
```