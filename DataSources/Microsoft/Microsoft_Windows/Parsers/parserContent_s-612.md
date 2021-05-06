#### Parser Content
```Java
{
Name = s-612
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "EventCode=612", "Audit Policy Change:" ]
  Fields = [
    """({event_name}Audit Policy Change)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """ComputerName=({host}[\w.\-]+)""",
    """({event_code}612)""",
    """Changed By:.*\s+User Name:\s+({user}[^\s]+)"""
    """\s+Domain Name:\s+({domain}[^\s]+)""",
    """\s+Logon ID:\s+\([^,]+,({logon_id}[^)]+)""",
    """Policy Change:\s+New Policy:(({policy}[^\n]+)\n+)+\s*Changed By:"""
  ]
  DupFields = [ "host->dest_host" ]
}
```