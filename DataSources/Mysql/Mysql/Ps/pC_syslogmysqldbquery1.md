#### Parser Content
```Java
{
Name = syslog-mysql-dbquery-1
    Vendor = Mysql
    Product = Mysql
    Lms = Direct
    DataType = "database-query"
    IsHVF = true
    TimeFormat = "yyyyMMdd HH:mm:ss"
    Conditions = [ """,QUERY,""", """CEF:""", """|SkyFormation Cloud Apps Security|""", """"ttam_category":"database/mysql"""" ]
    Fields = [
      """message"{1,20}:"{1,20}[^,]{0,2000}
```