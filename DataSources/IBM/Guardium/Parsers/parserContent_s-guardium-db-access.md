#### Parser Content
```Java
{
Name = s-guardium-db-access
  Vendor = IBM
  Product = Guardium
  Lms = Splunk
  DataType = "database-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|IBM|Guardium|""", """Object/Field=""", """App User Name="""]
  Fields = [
    """exabeam_host=({host}[^"]+)""",
    """:\d{1,100}\s{0,100}({host}[^\s]+)\s{0,100}\w+:""",
    """\d\d:\d\d:\d\d\s{0,100}({host}[^\.]+)\.({domain}[^\.]+)\..*?(?=\sauditprocess)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Start\sTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({process_name}[^\|]+)\|App\sUser\sName=({user}[^\|]+)\|Service\sName=({service_name}[^\|]+)\|Object\/Field=({database_object}[^\|]+)\|Sum\sOf\sRecord\sAffected=({sql_count}\d{1,100})""",
  ]
  DupFields = ["user->db_user"]
}
```