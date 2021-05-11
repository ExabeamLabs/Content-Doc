#### Parser Content
```Java
{
Name = oracle-db-access
  Vendor = Oracle
  Product = Oracle
  Lms = Direct
  DataType = "database-access"
  IsHVF = true
  TimeFormat = "dd-MM-yyyy HH:mm:ss"
  Conditions = [ """CONNECT_DATA=""", """SERVICE_NAME=""", """INSTANCE_NAME=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """({time}\d{1,100}-\w+-\d{1,100}\s{1,100}\d\d:\d\d:\d\d)\s""",
    """PORT=({dest_port}\d{1,100})""",
    """HOST=({dest_host}[\w\-.]+)\)\(USER=""",
    """HOST=({dest_ip}[A-Fa-f:\d.]+)\)\(PORT=""",
    """PROGRAM=({process_name}[^\)]+)""",
    """PROTOCOL=({protocol}[^\)]+)""",
    """SERVICE_NAME=({app}[^\)]+)""",
    """USER=({user}[^\)\s]+)""",
    """\(PORT=\d{1,100}\)\)\s{0,100}\*\s{0,100}({outcome}[^\s\*]+)""",
  ]
}
```