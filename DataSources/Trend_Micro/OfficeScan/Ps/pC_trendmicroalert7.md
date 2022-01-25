#### Parser Content
```Java
{
Name = trend-micro-alert-7
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ WFBSS-SVC-AC [LogWebReputation""" ]
  Fields = [
    """({host}\S+) WFBSS-SVC-AC""",
    """\d{1,100} ({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d) \d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100}""",
    """Device name="({src_host}[^"]{1,2000})""",
    """User="({user}[^"]{1,2000})""",
    """Risk Level="({alert_severity}[^"]{1,2000})""",
    """URL="({malware_url}[^"]{1,2000})""",
    """\[({alert_type}[^@]{1,2000})""",
  ]
  DupFields = [ "alert_type->alert_name" ]


}
```