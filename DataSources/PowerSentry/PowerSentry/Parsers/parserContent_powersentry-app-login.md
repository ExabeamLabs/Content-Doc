#### Parser Content
```Java
{
Name = powersentry-app-login
  Vendor = PowerSentry
  Product = PowerSentry
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ [Sentry""", """" logged in --""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[^\s]{1,2000}) \[({src_host}[^\]]{1,2000})\].+?User "({user}[^\s"]{1,2000})""",
    """connection source ({src_ip}[A-Fa-f:\d.]{1,2000}) using ({protocol}[^\s]{1,2000})""",
  ]
}
```