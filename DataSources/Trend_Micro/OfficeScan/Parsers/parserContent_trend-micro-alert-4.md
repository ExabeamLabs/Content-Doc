#### Parser Content
```Java
{
Name = trend-micro-alert-4
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ WFBSS-SVC-AC [LogPredictiveMachineLearning""" ]
  Fields = [
    """({host}\S+) WFBSS-SVC-AC""",
    """\d+ ({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d) \d+\.\d+\.\d+\.\d+""",
    """Device name="({src_host}[^"]+)""",
    """User="({user}[^"]+)""",
    """Unknown Threat="({alert_name}[^"]+)""",
    """File name="({file_name}[^"]+)""",
    """\[({alert_type}[^@]+)""",
  ]
}
```