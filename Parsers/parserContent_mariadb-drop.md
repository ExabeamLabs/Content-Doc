#### Parser Content
```Java
{
Name = mariadb-drop
  Vendor = MariaDB
  Product = MariaDB
  Lms = Direct
  DataType = "database-delete"
  TimeFormat = "yyyyMMdd HH:mm:ss"
  Conditions = [ """MariaDB:""","""DROP""" ]
  Fields = [
    """MariaDB:\s({time}\d+\s\d\d:\d\d:\d\d)""",
    """\:\d{2}\,({host}[^\,]+)?\,({user}[^\,]+)?\,({src_ip}[^,]+)?,({connection_id}\d+)?\,({query_id}\d+)?\,({db_operation}\w+)?\,({database_name}[^\,]+)?\,({object}[^\,]+)?"""
  ]
}
```