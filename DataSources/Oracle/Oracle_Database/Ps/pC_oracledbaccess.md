#### Parser Content
```Java
{
Name = oracle-db-access
  Vendor = Oracle
  Product = Oracle Database
  Lms = Direct
  DataType = "database-access"
  IsHVF = true
  TimeFormat = "dd-MM-yyyy HH:mm:ss"
  Conditions = [ """CONNECT_DATA=""", """SERVICE_NAME=""", """INSTANCE_NAME=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """({time}\d{1,100}-\w+-\d{1,100}\s{1,100}\d\d:\d\d:\d\d)\s""",
    """PORT=({dest_port}\d{1,100})""",
    """HOST=({dest_host}[\w\-.]{1,2000})\)\(USER=""",
    """HOST=({dest_ip}[A-Fa-f:\d.]{1,2000})\)\(PORT=""",
    """PROGRAM=({process_name}[^\)]{1,2000})""",
    """PROTOCOL=({protocol}[^\)]{1,2000})""",
    """SERVICE_NAME=({app}[^\)]{1,2000})""",
    """USER=({user}[^\)\s]{1,2000})""",
    """\(PORT=\d{1,100}\)\)\s{0,100}\*\s{0,100}({outcome}[^\s\*]{1,2000})""",
  ]


}
```