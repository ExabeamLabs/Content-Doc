#### Parser Content
```Java
{
Name = mariadb-query
  Vendor = MariaDB
  Product = MariaDB
  Lms = Direct
  DataType = "database-query"
  TimeFormat = "yyyyMMdd HH:mm:ss"
  Conditions = [ """MariaDB:""","""QUERY""" ]
  Fields = [
    """MariaDB:\s({time}\d+\s\d\d:\d\d:\d\d)""",
    """\:\d{2}\,({host}[^\,]+)?\,({user}[^\,]+)?\,({src_ip}[^,]+)?,({connection_id}\d+)?\,({query_id}\d+)?\,({db_operation}\w+)?\,({database_name}[^\,]+)?\,({db_query}.+)?\,\d+"""
  ]
}
```