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
      """({host}[\w\.-]+)\s{1,100}mysql-server_auditing:""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\S+\s{1,100}\S+\s{1,100}mysql-server_auditing:""",
      """({app}mysql)""",
      """mysql-server_auditing:\s{0,100}({database_name}[^,]+)\s{0,100}
```