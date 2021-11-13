#### Parser Content
```Java
{
Name = syslog-mysql-dbquery-2
  Vendor = Mysql
  Product = Mysql
  Lms = Direct
  DataType = "database-query"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|SkyFormation Cloud Apps Security|""", """"ttam_category":"database/mysql"""", """"ttam_service":"database"""", """logger.account""" ]
  Fields = [
    """timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""",
    """ttam_reporter":"({host}[^"]{1,2000})"""",
    """message":"\s{0,100}({db_query}({db_operation}\w+)[^"]{0,2000}?)\s{0,100}"(,"\w+":|\})""",
    """message":"([^,]{1,2000

}
```