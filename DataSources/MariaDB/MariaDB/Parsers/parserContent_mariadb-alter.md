#### Parser Content
```Java
{
Name = mariadb-alter
  Vendor = MariaDB
  Product = MariaDB
  Lms = Direct
  DataType = "database-update"
  TimeFormat = "yyyyMMdd HH:mm:ss"
  Conditions = [ """MariaDB:""","""ALTER""" ]
  Fields = [
    """MariaDB:\s({time}\d{1,100}\s\d\d:\d\d:\d\d)""",
    """\:\d{2}\,({host}[^\,]{1,2000})?\,({user}[^\,]{1,2000})?\,({src_ip}[^,]{1,2000})?,({connection_id}\d{1,100})?\,({query_id}\d{1,100})?\,({db_operation}\w+)?\,({database_name}[^\,]{1,2000})?\,({object}[^\,]{1,2000})?"""
  ]
}
```