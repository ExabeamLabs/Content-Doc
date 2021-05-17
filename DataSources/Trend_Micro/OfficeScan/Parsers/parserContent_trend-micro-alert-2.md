#### Parser Content
```Java
{
Name = trend-micro-alert-2
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ WFBSS-SVC-AC [LogBehaviorMonitoring""", """Security Threat="""" ]
  Fields = [
    """({host}\S+) WFBSS-SVC-AC""",
    """\d{1,100} ({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d) \d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100}""",
    """Device name="({src_host}[^"]{1,2000})""",
    """User="({user}[^"]{1,2000})""",
    """Security Threat="({alert_name}[^"]{1,2000})""",
    """Subject="({process}({directory}[^"]{1,2000}?)\\({process_name}[^\\"]{1,2000}))"""",
    """\[({alert_type}[^@]{1,2000})""",
  ]
}
```