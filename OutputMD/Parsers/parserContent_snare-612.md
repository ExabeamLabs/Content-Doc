#### Parser Content
```Java
{
Name = snare-612
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "\t612\t", "Audit Policy Change:" ]
  Fields = [
    """({event_name}Audit Policy Change)""",
    """\s+(Information|Audit Success|Success Audit)\s+({host}[\w.\-]+)""",
    """\s+(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)\s+""",
    """({event_code}612)""",
    """\s+User Name:\s+({user}.+?)\s+Domain""",
    """\s+Domain Name:\s+({domain}[^\s]+)""",
    """\s+Logon ID:\s+\([^,]+,({logon_id}[^)]+)""",
    """\s+New Policy:\s+({policy}.+?)\s+Changed By"""
  ]
  DupFields = [ "host->dest_host" ]
}
```