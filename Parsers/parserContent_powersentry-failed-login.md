#### Parser Content
```Java
{
Name = powersentry-failed-login
  Vendor = PowerSentry
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ [Sentry""", """unsuccessfully to log in """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[^\s]+) \[({src_host}[^\]]+)\].+?User "({user}[^\s"]+)""",
    """connection source ({src_ip}[A-Fa-f:\d.]+) using ({protocol}[^\s]+)""",
  ]
}
```