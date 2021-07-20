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
    """({outcome}AuthReject) ({host}[\w\-.]{1,2000}) \[({time}\d{1,100}\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [+-]\d{1,100})\]""",
    """cn=({user}[^\s,]{1,2000}),ou=({domain}[^,]{1,2000}),o=({group}[^,"]{1,2000})"\s{1,100}"({app}\S+)\s""",
    """"({src_ip}[A-Fa-f:\d.]{1,2000}) uid=({user}[^\s,]{1,2000}),o=({group}[^,]{1,2000}),dc=({domain}[^,]{1,2000}),.*?" "({app}.+?) \S+ ({resource}[^"\s]{1,2000})" \[.+?error:\s{0,100}({failure_reason}[^\(]{1,2000}?)\s{0,100}\(({failure_code}[^\)]{1,2000})\)""",
  ]
}
```