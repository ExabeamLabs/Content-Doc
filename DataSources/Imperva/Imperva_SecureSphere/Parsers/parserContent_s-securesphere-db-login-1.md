#### Parser Content
```Java
{
Name = s-securesphere-db-login-1
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Splunk
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """ os_user=""", """ dbName=""", """ operation=Login""" ]
  Fields = [
    """event_time=({time}\d\d \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d+ \d\d:\d\d:\d\d ({host}[\w\-.]+)""",
    """user=({db_user}[^\s]+)""",
    """os_user=({user}[^\s]+)""",
    """source_ip=({src_ip}[A-Fa-f:\d.]+)""",
    """destination_ip=({dest_ip}[A-Fa-f:\d.]+)""",
    """dbName=({database_name}.+?)\s*(\w+=|$)""",
    """sqlError="({reason}[^"]+?)\s*(\w+=|$)""",
  ]
  DupFields = [ "db_user->account" ]
}
```