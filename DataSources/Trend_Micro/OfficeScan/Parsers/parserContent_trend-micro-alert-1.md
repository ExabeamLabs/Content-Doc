#### Parser Content
```Java
{
Name = trend-micro-alert-1
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ WFBSS-SVC-AC [LogVirus""", """Virus/Malware Name="""" ]
  Fields = [
    """({host}\S+) WFBSS-SVC-AC""",
    """\d{1,100} ({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d) \d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100}""",
    """Device name="({src_host}[^"]+)""",
    """User="({user}[^"]+)""",
    """Virus\/Malware Name="({alert_name}[^"]+)""",
    """File name="({file_name}[^"]+)""",
    """\[({alert_type}[^@]+)""",
  ]
}
```