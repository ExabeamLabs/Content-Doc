#### Parser Content
```Java
{
Name = securesphere-db-cuseqsv
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-operation"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """imperva_version=""", """event_type=""", """sql_error=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_raw=.*?({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """(,\s{1,100}|,\s{0,100})dest_ip=\s{0,100}({host}\S+?)\s{0,100}(,|$)""",
    """(,\s{1,100}|,\s{0,100})hostname=\s{0,100}({host}[\w\.-]{1,2000})\s{0,100}(,|$)""",
    """=(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)(  \d| \d\d) \d{1,2}:\d\d:\d\d\s{1,100}({host}[\w\.-]{1,2000})""",
    """(,\s{1,100}|,\s{0,100})src_ip=\s{0,100}(0\.0\.0\.0|({src_ip}\S+?))\s{0,100}(,|$)""",
    """(,\s{1,100}|,\s{0,100})dest_ip=\s{0,100}({dest_ip}\S+?)\s{0,100}(,|$)""",
    """(,\s{1,100}|,\s{0,100})hostname=\s{0,100}({dest_host}[\w\.-]{1,2000})\s{0,100}(,|$)""",
    """(,\s{1,100}|,\s{0,100})event_type=\s{0,100}(|({log_type}.+?))\s{0,100}(,|$)""",
    """(,\s{1,100}|,\s{0,100})database_user=\s{0,100}(({domain}[^,]{1,2000}?)\\)?({db_user}[^\s,][^,@]{0,2000}?)\s{0,100}(,|$)""",
    """(,\s{1,100}|,\s{0,100})database_user=\s{0,100}({db_user}[^\s\\,@][^\\,@]{0,2000}?)(@({domain}[^,\s]{1,2000}))?\s{0,100}(,|$)""",
    """(,\s{1,100}|,\s{0,100})source_application=\s{0,100}(|({app}[^@]{1,2000}?)(\s{0,100}@\s{0,100}({src_host}[\w\.-]{1,2000}).*?)?)\s{0,100}(,|$)""",
    """(,\s{1,100}|,\s{0,100})application_name=\s{0,100}(|({app}.+?))\s{0,100}(,|$)""",
    """({database_name}database)""",
    """(,\s{1,100}|,\s{0,100})database=\s{0,100}(|({database_name}.+?))\s{0,100}(,|$)""",
    """(,\s{1,100}|,\s{0,100})response_size=\s{0,100}(|({response_size}\d{1,100}))\s{0,100}(,|$)""",
    """(,\s{1,100}|,\s{0,100})sql_error=\s{0,100}(|({sql_error}.+?))\s{0,100}(,|$)""",
    """(,\s{1,100}|,\s{0,100})rawquery=[^,]{0,2000}({db_operation}(insert|delete|truncate\s{1,100}\w+|drop\s{1,100}\w+|alter\s{1,100}\w+|create\s{1,100}\w+|update|enable\s{1,100}\w+|disable\s{1,100}\w+|merge|delete|select|dbcc))"""
    """(,\s{1,100}|,\s{0,100})operation=\s{0,100}(|(L|l)ogin|(L|l)ogout|({db_operation}.+?))\s{0,100}(,|$)""",
    """(,\s{1,100}|,\s{0,100})affected_rows=\s{0,100}(|({affected_rows}\d{1,100}))\s{0,100}(,|$)""",
    """(,\s{1,100}|,\s{0,100})rawquery=\s{0,100}(|({db_query}.+?))\s{0,100}(,\s{0,100}\w+=|$)""",
    """(,\s{1,100}|,\s{0,100})schema=\s{0,100}(|({database_schema}.+?))\s{0,100}(,|$)""",
    """\Wos_user=({user}[^\s,]{1,2000})"""
  ]
  DupFields = [ "db_user->account" ]
}
```