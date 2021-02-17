#### Parser Content
```Java
{
Name = syslog-mysql-dbquery
    Vendor = Mysql
  Product = Mysql
    Lms = Direct
    DataType = "database-operation"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """mysql-server_auditing:""", """,QUERY,""" ]
    Fields = [
      """({host}[\w\.-]+)\s+mysql-server_auditing:""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\S+\s+\S+\s+mysql-server_auditing:""",
      """({app}mysql)""",
      """mysql-server_auditing:\s*({database_name}[^,]+)\s*,""",
      """mysql-server_auditing:\s*([^,]*,)\s*({user}[^,]+)\s*,""",
      """mysql-server_auditing:\s*([^,]*,){2}\s*({src_host}[^,]+)\s*,""",
      """,QUERY,({database_schema}[^,]+),""",
      """,QUERY,[^,]*,'\s*({db_operation}\S+)""",
      """,QUERY,[^,]*,'\s*({db_query}.*?[^\\])\s*',({error_code}\d+)?\s*$"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```