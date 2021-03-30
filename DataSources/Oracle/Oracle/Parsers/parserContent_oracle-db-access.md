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
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """({time}\d+-\w+-\d+\s+\d\d:\d\d:\d\d)\s""",
    """PORT=({dest_port}\d+)""",
    """HOST=({dest_host}[\w\-.]+)\)\(USER=""",
    """HOST=({dest_ip}[A-Fa-f:\d.]+)\)\(PORT=""",
    """PROGRAM=({process_name}[^\)]+)""",
    """PROTOCOL=({protocol}[^\)]+)""",
    """SERVICE_NAME=({app}[^\)]+)""",
    """USER=({user}[^\)\s]+)""",
    """\(PORT=\d+\)\)\s*\*\s*({outcome}[^\s\*]+)""",
  ]
}
```