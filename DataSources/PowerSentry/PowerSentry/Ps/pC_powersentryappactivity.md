#### Parser Content
```Java
{
Name = powersentry-app-activity
  Vendor = PowerSentry
  Product = PowerSentry
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ [Sentry""", """ primary host changed to """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[^\s]{1,2000}) \[({src_host}[^\]]{1,2000})\].+? by user "({user}[^\s"]{1,2000})""",
    """({activity}primary host changed)""",
  ]
}
```