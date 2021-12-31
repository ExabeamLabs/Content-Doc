#### Parser Content
```Java
{
Name = mariadb-failedconnect
  Vendor = MariaDB
  Product = MariaDB
  Lms = Direct
  DataType = "database-failed-login"
  TimeFormat = "yyyyMMdd HH:mm:ss"
  Conditions = [ """ mariadb """,""",FAILED_CONNECT,""" ]
  Fields = [
    """ mariadb ({time}\d{1,8} \d\d:\d\d:\d\d),""",
    """\:\d{2}\,(|({host}[^\,]{1,2000}))\,(|({user}[^\,]{1,2000}))\,(|({src_ip}[^,]{1,2000})),(|({connection_id}\d{1,100}))\,(|({query_id}\d{1,100}))\,(|({db_operation}\w+))\,(|({database_name}[^\,]{1,2000}))\,(|({object}[^\,]{1,2000})),"""
  ]


}
```