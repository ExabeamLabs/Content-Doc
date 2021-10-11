#### Parser Content
```Java
{
Name = syslog-mysql-dbwrite
    Vendor = Mysql
  Product = Mysql
    Lms = Direct
    DataType = "database-operation"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """mysql-server_auditing:""", """,WRITE,""" ]
    Fields = [
      """({host}[\w\.-]{1,2000})\s{1,100}mysql-server_auditing:""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\S+\s{1,100}\S+\s{1,100}mysql-server_auditing:""",
      """({app}mysql)""",
      """mysql-server_auditing:\s{0,100}({database_name}[^,]{1,2000})\s{0,100},""",
      """mysql-server_auditing:\s{0,100}([^,]{0,2000},)\s{0,100}({user}[^,]{1,2000})\s{0,100},""",
      """mysql-server_auditing:\s{0,100}([^,]{0,2000},){2}\s{0,100}({src_host}[^,]{1,2000})\s{0,100},""",
      """({db_operation}WRITE)""",
      """,WRITE,\s{0,100}({database_name}[^,]{1,2000})\s{0,100},""",
      """,WRITE,[^,]{1,2000},\s{0,100}({table_name}[^,]{1,2000})\s{0,100}""",
    ]
    DupFields = [ "host->dest_host" ]
  }
```