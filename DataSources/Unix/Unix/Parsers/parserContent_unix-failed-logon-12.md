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
    """({time}\w+\s+\d+ \d\d:\d\d:\d\d \d\d\d\d)""",
    """\d\d:\d\d:\d\d \d\d\d\d ({host}[^\s]+)""",
    """({event_name}SSHS_LOG)""",
    """Authentication failed for ({user}[^\s]+) from ({src_ip}[a-fA-F:\d\.]+)""",
    """because of ({failure_reason}[^.]+)\s+"""
  ]
  DupFields = [ "host->dest_host" ]
}
```