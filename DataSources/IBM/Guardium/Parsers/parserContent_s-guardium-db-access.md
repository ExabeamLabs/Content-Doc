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
    """exabeam_host=({host}[^"]{1,2000})""",
    """:\d{1,100}\s{0,100}({host}[^\s]{1,2000})\s{0,100}\w+:""",
    """\d\d:\d\d:\d\d\s{0,100}({host}[^\.]{1,2000})\.({domain}[^\.]{1,2000})\..*?(?=\sauditprocess)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Start\sTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({process_name}[^\|]{1,2000})\|App\sUser\sName=({user}[^\|]{1,2000})\|Service\sName=({service_name}[^\|]{1,2000})\|Object\/Field=({database_object}[^\|]{1,2000})\|Sum\sOf\sRecord\sAffected=({sql_count}\d{1,100})""",
  ]
  DupFields = ["user->db_user"]
}
```