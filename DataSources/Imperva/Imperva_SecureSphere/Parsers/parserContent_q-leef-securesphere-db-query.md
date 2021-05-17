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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """\|devTime=({time}\d{1,100} \w+ \d{1,100} \d\d:\d\d:\d\d)""",
    """usrName=(({domain}[^\\|]{1,2000})(\\))?({user}[^|]{1,2000})""",
    """ApplicationName=({app}[^|]{1,2000})""",
    """Service Name=({service_name}[^|]{1,2000})""",
    """Server Group=({server_group}[^|]{1,2000})""",
    """Database=({database_name}[^|]{1,2000})""",
    """src=((?=0\.0\.0\.0)|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """dst=((?=0\.0\.0\.0)|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\|Operation=(?: |({db_operation}[^|]{1,2000}))""",
    """\|Response Size=({response_size}\d{1,100})"""
  ]
  DupFields = [ "src_ip->host" ]
}
```