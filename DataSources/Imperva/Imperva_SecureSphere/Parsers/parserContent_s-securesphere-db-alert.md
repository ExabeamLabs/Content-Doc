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
    """exabeam_host=({host}[\w\-.]+)""",
    """\sduser=(?:n\/a|({db_user}[^,]+))""",
    """\sos-user=({user}[^,]+)""",
    """\sApplicationName=(?: |({app}[^,]+))""",
    """\sServiceName=(?: |({service_name}[^,]+))""",
    """\sServerGroup=(?: |({server_group}[^,]+))""",
    """\sdatabase=(?: |({database_name}[^,]+))""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\salert=({alert_name}[^,]+)""",
    """,\sPolicy=({alert_type}[^,]+)""",
    """\ssev=({alert_severity}[^,]+)"""
    """\sDescription=({additional_info}.+?)\s{1,100}$"""
  ]
  DupFields = [ "db_user->account" ]
}
```