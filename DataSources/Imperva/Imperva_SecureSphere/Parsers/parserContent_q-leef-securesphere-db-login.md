#### Parser Content
```Java
{
Name = q-leef-securesphere-db-login
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = QRadar
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "dd MMMM yyyy HH:mm:ss"
  Conditions = [ """Authenticated=True""", """Event Type=Login""", """LEEF:""", """|SecureSphere|""", """User Type=Valid|""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """\|devTime=({time}\d{1,100} \w+ \d{1,100} \d\d:\d\d:\d\d)""",
    """usrName=(({domain}[^\\|]+)(\\))?({user}[^|]+)""",
    """ApplicationName=({app}[^|]+)""",
    """src=((?=0\.0\.0\.0)|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """dst=((?=0\.0\.0\.0)|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """Service Name=({service_name}[^|]+)""",
    """Server Group=({server_group}[^|]+)""",
    """Database=({database_name}[^|]+)""",
  ]
  DupFields = [ "src_ip->host" ]
}
```