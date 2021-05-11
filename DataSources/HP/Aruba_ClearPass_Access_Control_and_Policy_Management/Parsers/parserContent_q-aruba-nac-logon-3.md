#### Parser Content
```Java
{
Name = q-aruba-nac-logon-3
  Vendor = HP
  Product = Aruba ClearPass Access Control and Policy Management
  Lms = QRadar
  DataType = "nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
  Conditions = [ """ Radius Accounting """, """RADIUS.Acct-Timestamp=""" ]
  Fields = [
    """RADIUS\.Acct-Timestamp=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d(\.\d{1,100})?[\+\-]\d{1,100})""",
    """\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d,\d{1,100} ({host}[\w\-.]+)""",
    """RADIUS\.Acct-Username=(?:({user_type}host)/)?(({domain}[^\\\s,]+)\\+)?(anonymous|({user}[^\\\s,@]+))""",
    """RADIUS\.Acct-Username=({user_email}[^\\\s,@]+@[^\\\s,@]+)""",
    """RADIUS\.Acct-Service-Name=({network}[^,]+)""",
    """RADIUS\.Acct-NAS-IP-Address=({dest_ip}[A-Fa-f:\d.]+)""",
    """RADIUS\.Acct-Framed-IP-Address=({src_ip}[A-Fa-f:\d.]+)""",
  ]
  DupFields = [ "host->auth_server" ]
}
```