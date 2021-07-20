#### Parser Content
```Java
{
Name = s-securesphere-db-alert
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Splunk
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ Imperva Inc.|SecureSphere,""", """cat=Alert""", """, Policy=""" ]
  Fields = [
    """exabeam_raw=.*?({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """\sduser=(?:n\/a|({db_user}[^,]{1,2000}))""",
    """\sos-user=({user}[^,]{1,2000})""",
    """\sApplicationName=(?: |({app}[^,]{1,2000}))""",
    """\sServiceName=(?: |({service_name}[^,]{1,2000}))""",
    """\sServerGroup=(?: |({server_group}[^,]{1,2000}))""",
    """\sdatabase=(?: |({database_name}[^,]{1,2000}))""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\salert=({alert_name}[^,]{1,2000})""",
    """,\sPolicy=({alert_type}[^,]{1,2000})""",
    """\ssev=({alert_severity}[^,]{1,2000})"""
    """\sDescription=({additional_info}.+?)\s{1,100}$"""
  ]
  DupFields = [ "db_user->account" ]
}
```