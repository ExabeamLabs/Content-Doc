#### Parser Content
```Java
{
Name = s-securesphere-db-query
  Vendor = Imperva 
  Product = Imperva SecureSphere
  Lms = Splunk
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """ os_user=""", """ dbName=""", """ operation=""", """ query="""" ]
  Fields = [
    """event_time=({time}\d\d \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d+ \d\d:\d\d:\d\d ({host}[\w\-.]+)""",
    """user=({db_user}[^\s]+)""",
    """os_user=({user}[^\s]+)""",
    """source_ip=({src_ip}[A-Fa-f:\d.]+)""",
    """destination_ip=({dest_ip}[A-Fa-f:\d.]+)""",
    """dbName=({database_name}.+?)\s*(\w+=|$)""",
    """operation=({db_operation}.+?)\s*(\w+=|$)""",
    """query="({db_query}[^"]+)""",
    """response_size=({response_size}\d+)""",
  ]
  DupFields = [ "db_user->account" ]
}
```