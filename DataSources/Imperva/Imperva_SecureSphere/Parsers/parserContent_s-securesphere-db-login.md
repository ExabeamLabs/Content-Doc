#### Parser Content
```Java
{
Name = s-securesphere-db-login
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Splunk
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ Imperva Inc.|SecureSphere,""", """event-type=Login""", """user-authenticated=True""" ]
  Fields = [
    """exabeam_raw=.*?({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """\sdb-user=({db_user}[^,]{1,2000})""",
    """\sos-user=({user}[^,]{1,2000})""",
    """\sapplication-name=({app}[^,]{1,2000})""",
    """\sservice-name=({service_name}[^,]{1,2000})""",
    """\sserver-group=({server_group}[^,]{1,2000})""",
    """\sdatabase=(?: |({database_name}[^,]{1,2000}))""",
    """\ssource-ip=(?:0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\sdest-ip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    """\ssource-host=({src_host}[^,]{1,2000})"""
  ]
  DupFields = [ "db_user->account" ]
}
```