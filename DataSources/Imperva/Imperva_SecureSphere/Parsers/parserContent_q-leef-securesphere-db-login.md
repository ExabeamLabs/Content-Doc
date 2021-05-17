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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """\|devTime=({time}\d{1,100} \w+ \d{1,100} \d\d:\d\d:\d\d)""",
    """usrName=(({domain}[^\\|]{1,2000})(\\))?({user}[^|]{1,2000})""",
    """ApplicationName=({app}[^|]{1,2000})""",
    """src=((?=0\.0\.0\.0)|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """dst=((?=0\.0\.0\.0)|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """Service Name=({service_name}[^|]{1,2000})""",
    """Server Group=({server_group}[^|]{1,2000})""",
    """Database=({database_name}[^|]{1,2000})""",
  ]
  DupFields = [ "src_ip->host" ]
}
```