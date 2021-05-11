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
    """({outcome}AuthReject) ({host}[\w\-.]+) \[({time}\d{1,100}\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [+-]\d{1,100})\]""",
    """cn=({user}[^\s,]+),ou=({domain}[^,]+),o=({group}[^,"]+)"\s{1,100}"({app}\S+)\s""",
    """"({src_ip}[A-Fa-f:\d.]+) uid=({user}[^\s,]+),o=({group}[^,]+),dc=({domain}[^,]+),.*?" "({app}.+?) \S+ ({resource}[^"\s]+)" \[.+?error:\s{0,100}({failure_reason}[^\(]+?)\s{0,100}\(({failure_code}[^\)]+)\)""",
  ]
}
```