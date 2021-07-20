#### Parser Content
```Java
{
Name = unix-su-37
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ su: from """, """ Message forwarded from """]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Message forwarded from (::ffff:)?({host}[^\s:]{1,2000})""",
    """({event_code}su)""",
    """su: from ({user}\w+) to ({account}\w+) at ({process_directory}.*?)\?*\s{0,100}$"""
  ]
}
```