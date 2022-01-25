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
      """({host}[\w\.-]{1,2000})\s{1,100}mysql-server_auditing:""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\S+\s{1,100}\S+\s{1,100}mysql-server_auditing:""",
      """({app}mysql)""",
      """mysql-server_auditing:\s{0,100}({database_name}[^,]{1,2000})\s{0,100}
```