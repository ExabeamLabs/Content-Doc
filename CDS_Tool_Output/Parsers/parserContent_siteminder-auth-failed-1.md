#### Parser Content
```Java
{
Name = siteminder-auth-failed-1
  Vendor = SiteMinder
  Product = SiteMinder
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
  Conditions = [ """AuthReject """, """,o=""", """ [""", """] """" ]
  Fields = [
    """({outcome}AuthReject) ({host}[\w\-.]+) \[({time}\d+\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [+-]\d+)\]""",
    """cn=({user}[^\s,]+),ou=({domain}[^,]+),o=({group}[^,"]+)"\s+"({app}\S+)\s""",
    """"({src_ip}[A-Fa-f:\d.]+) uid=({user}[^\s,]+),o=({group}[^,]+),dc=({domain}[^,]+),.*?" "({app}.+?) \S+ ({resource}[^"\s]+)" \[.+?error:\s*({failure_reason}[^\(]+?)\s*\(({failure_code}[^\)]+)\)""",
  ]
}
```