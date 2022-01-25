#### Parser Content
```Java
{
Name = oracle-db-access-1
  Vendor = Oracle
  Product = Oracle Database
  Lms = Direct
  DataType = "database-access"
  IsHVF = true
  TimeFormat = "dd-MMM-yyyy HH:mm:ss"
  Conditions = [ """[LNX]""", """ Oracle """, """CONNECT_DATA=""" ]
  Fields = [
    """({host}[\w.\-]{1,2000})\s{1,100}Oracle(\s{1,100}\S+){3}\s{1,100}({time}\d\d-\w+-\d\d\d\d \d\d:\d\d:\d\d)""",
    """\(USER=({user}[^\)]{1,2000}?)\)""",
    """\(COMMAND=({command}[^\)]{1,2000}?)\)""",
    """\(SERVICE=({service_name}[^\)]{1,2000}?)\)""",
    """\(HOST=({dest_host}[^\)]{1,2000}?)\)""",
    """\(PROTOCOL=({protocol}[^\)]{1,2000}?)\)""",
    """\(PORT=({dest_port}[^\)]{1,2000}?)\)""",
    """\(PROGRAM=({process}[^\)]{1,2000}?)\)"""
  ]


}
```