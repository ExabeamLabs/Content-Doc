#### Parser Content
```Java
{
Name = unix-failed-logon-12
  Vendor = Unix
  Product = Unix
  Lms = Syslog
  DataType = "failed-logon"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """Authentication failed for""", """ from """, """SSHS_LOG: """ ]
  Fields = [
    """({time}\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d \d\d\d\d)""",
    """\d\d:\d\d:\d\d \d\d\d\d ({host}[^\s]{1,2000})""",
    """({event_name}SSHS_LOG)""",
    """Authentication failed for ({user}[^\s]{1,2000}) from ({src_ip}[a-fA-F:\d\.]{1,2000})""",
    """because of ({failure_reason}[^.]{1,2000})\s{1,100}"""
  ]
  DupFields = [ "host->dest_host" ]


}
```