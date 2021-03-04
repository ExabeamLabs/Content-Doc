#### Parser Content
```Java
{
Name = powersentry-app-activity
  Vendor = PowerSentry
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ [Sentry""", """ primary host changed to """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[^\s]+) \[({src_host}[^\]]+)\].+? by user "({user}[^\s"]+)""",
    """({activity}primary host changed)""",
  ]
}
```