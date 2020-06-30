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
    """exabeam_host=({host}[\w\-.]+)""",
    """\sdb-user=({db_user}[^,]+)""",
    """\sos-user=({user}[^,]+)""",
    """\sapplication-name=({app}[^,]+)""",
    """\sservice-name=({service_name}[^,]+)""",
    """\sserver-group=({server_group}[^,]+)""",
    """\sdatabase=(?: |({database_name}[^,]+))""",
    """\ssource-ip=(?:0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\sdest-ip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    """\ssource-host=({src_host}[^,]+)"""
  ]
  DupFields = [ "db_user->account" ]
}
```