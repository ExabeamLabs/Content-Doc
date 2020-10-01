#### Parser Content
```Java
{
Name = q-leef-securesphere-db-query
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = QRadar
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "dd MMMM yyyy HH:mm:ss"
  Conditions = [ """Authenticated=True""", """Event Type=Query""", """LEEF:""", """|SecureSphere|""", """User Type=Valid|""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """\|devTime=({time}\d+ \w+ \d+ \d\d:\d\d:\d\d)""",
    """usrName=(({domain}[^\\|]+)(\\))?({user}[^|]+)""",
    """ApplicationName=({app}[^|]+)""",
    """Service Name=({service_name}[^|]+)""",
    """Server Group=({server_group}[^|]+)""",
    """Database=({database_name}[^|]+)""",
    """src=((?=0\.0\.0\.0)|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """dst=((?=0\.0\.0\.0)|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\|Operation=(?: |({db_operation}[^|]+))""",
    """\|Response Size=({response_size}\d+)"""
  ]
  DupFields = [ "src_ip->host" ]
}
```