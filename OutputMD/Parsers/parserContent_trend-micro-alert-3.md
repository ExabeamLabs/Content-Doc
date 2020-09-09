#### Parser Content
```Java
{
Name = trend-micro-alert-3
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ WFBSS-SVC-AC [LogDeviceControl""" ]
  Fields = [
    """({host}\S+) WFBSS-SVC-AC""",
    """\d+ ({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d) \d+\.\d+\.\d+\.\d+""",
    """Device name="({src_host}[^"]+)""",
    """User="({user}[^"]+)""",
    """Subject="({file_path}.+?\\({file_name}[^\\"]+))"""",
    """\[({alert_type}[^@]+)""",
  ]
  DupFields = [ "file_name->alert_name" ]
}
```