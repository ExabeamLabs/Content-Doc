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
    """\d\d:\d\d:\d\d ({host}[^\s]+) \[({src_host}[^\]]+)\].+?User "({user}[^\s"]+)""",
    """connection source ({src_ip}[A-Fa-f:\d.]+) using ({protocol}[^\s]+)""",
  ]
}
```