#### Parser Content
```Java
{
Name = q-aruba-nac-logon-6
  DataType = "nac-logon"
  Conditions = [ """ Guest """, """Common.Request-Timestamp=""" ]

q-aruba-nac-logon = {
  Vendor = HP
  Product = Aruba ClearPass Access Control and Policy Management
  Lms = QRadar
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Fields = [
    """Common\.Request-Timestamp=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d(\.\d{1,100})?[\+\-]\d{1,100})""",
    """\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d,\d{1,100} ({host}[\w\-.]{1,2000})""",
    """Common\.Username=(?:({user_type}host)/)?(({domain}[^\\\s,]{1,2000})\\+)?(anonymous|({user}[^\\\s,@]{1,2000}))""",
    """Common\.Username=({user_email}[^\\\s,@]{1,2000}@[^\\\s,@]{1,2000})""",
    """Common\.Service=({network}[^,]{1,2000})""",
    """Common\.Host-MAC-Address=({src_mac}\w+)""",
    """Common\.NAS-IP-Address=({dest_ip}[A-Fa-f:\d.]{1,2000})"""
  ]
  DupFields = [ "host->auth_server" 
}
```