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
    """\w+ \d{1,100} \d\d:\d\d:\d\d ({host}[\w\-.]{1,2000})""",
    """user=({db_user}[^\s]{1,2000})""",
    """os_user=({user}[^\s]{1,2000})""",
    """source_ip=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """destination_ip=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """dbName=({database_name}.+?)\s{0,100}(\w+=|$)""",
    """sqlError="({reason}[^"]{1,2000}?)\s{0,100}(\w+=|$)""",
  ]
  DupFields = [ "db_user->account" ]
}
```