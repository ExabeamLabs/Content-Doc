#### Parser Content
```Java
{
Name = s-517
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "EventCode=517", "The audit log was cleared" ]
  Fields = [
    """({event_name}The audit log was cleared)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """ComputerName=({host}[\w.\-]+)""",
    """Client User Name:\s{1,100}({user}[^\s]+)""",
    """({event_code}517)""",
    """\s{1,100}Client Domain:\s{1,100}({domain}[^\s]+)""",
    """\s{1,100}Client Logon ID:\s{1,100}\([^,]+,({logon_id}[^)]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```