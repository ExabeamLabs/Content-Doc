#### Parser Content
```Java
{
Name = snare-517
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "\t517\t", "The audit log was cleared" ]
  Fields = [
    """({event_name}The audit log was cleared)""",
    """\s+(Information|Audit Success|Success Audit)\s+({host}[\w.\-]+)""",
    """\s+(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)\s+""",
    """({event_code}517)""",
    """({event_name}The audit log was cleared)""",
    """\s+Client User Name:\s+({user}.+?)\s+Client Domain""",
    """\s+Client Domain:\s+({domain}[^\s]+)""",
    """\s+Client Logon ID:\s+\([^,]+,({logon_id}[^)]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```