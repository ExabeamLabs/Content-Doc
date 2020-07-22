#### Parser Content
```Java
{
Name = securesphere-db-cuseqsv
  Vendor = Imperva 
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-operation"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """imperva_version=""", """event_type=""", """sql_error=""" ]
  Fields = [
    """exabeam_raw=.*?({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w\-.]+)""",
    """(,\s+|,\s*)dest_ip=\s*({host}\S+?)\s*(,|$)""",
    """(,\s+|,\s*)hostname=\s*({host}[\w\.-]+)\s*(,|$)""",
    """=(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)(  \d| \d\d) \d{1,2}:\d\d:\d\d\s+({host}[\w\.-]+)""",
    """(,\s+|,\s*)src_ip=\s*(0\.0\.0\.0|({src_ip}\S+?))\s*(,|$)""",
    """(,\s+|,\s*)dest_ip=\s*({dest_ip}\S+?)\s*(,|$)""",
    """(,\s+|,\s*)hostname=\s*({dest_host}[\w\.-]+)\s*(,|$)""",
    """(,\s+|,\s*)event_type=\s*(|({event_type}.+?))\s*(,|$)""",
    """(,\s+|,\s*)database_user=\s*(({domain}[^,]+?)\\)?({db_user}[^\s,][^,@]*?)\s*(,|$)""",
    """(,\s+|,\s*)database_user=\s*({db_user}[^\s\\,@][^\\,@]*?)(@({domain}[^,\s]+))?\s*(,|$)""",
    """(,\s+|,\s*)source_application=\s*(|({app}[^@]+?)(\s*@\s*({src_host}[\w\.-]+).*?)?)\s*(,|$)""",
    """(,\s+|,\s*)application_name=\s*(|({app}.+?))\s*(,|$)""",
    """({database_name}database)""",
    """(,\s+|,\s*)database=\s*(|({database_name}.+?))\s*(,|$)""",
    """(,\s+|,\s*)response_size=\s*(|({response_size}\d+))\s*(,|$)""",
    """(,\s+|,\s*)sql_error=\s*(|({sql_error}.+?))\s*(,|$)""",
    """(,\s+|,\s*)rawquery=[^,]*({db_operation}(insert|delete|truncate\s+\w+|drop\s+\w+|alter\s+\w+|create\s+\w+|update|enable\s+\w+|disable\s+\w+|merge|delete|select|dbcc))"""
    """(,\s+|,\s*)operation=\s*(|(L|l)ogin|(L|l)ogout|({db_operation}.+?))\s*(,|$)""",
    """(,\s+|,\s*)affected_rows=\s*(|({affected_rows}\d+))\s*(,|$)""",
    """(,\s+|,\s*)rawquery=\s*(|({db_query}.+?))\s*(,\s*\w+=|$)""",
    """(,\s+|,\s*)schema=\s*(|({database_schema}.+?))\s*(,|$)""",
    """\Wos_user=({user}[^\s,]+)"""
  ]
  DupFields = [ "db_user->account" ]
}
```