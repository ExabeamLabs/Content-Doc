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
    """MariaDB:\s({time}\d{1,100}\s\d\d:\d\d:\d\d)""",
    """\:\d{2}\,({host}[^\,]+)?\,({user}[^\,]+)?\,({src_ip}[^,]+)?,({connection_id}\d{1,100})?\,({query_id}\d{1,100})?\,({db_operation}\w+)?\,({database_name}[^\,]+)?\,({db_query}.+)?\,\d{1,100}"""
  ]
}
```