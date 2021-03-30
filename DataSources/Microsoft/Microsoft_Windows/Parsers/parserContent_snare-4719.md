#### Parser Content
```Java
{
Name = snare-4719
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "\t4719\t", "System audit policy was changed" ]
  Fields = [
    """({event_name}System audit policy was changed)""",
    """\s+(Information|Audit Success|Success Audit)\s+({host}[\w.\-]+)""",
    """\s+(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)\s+""",
    """({event_code}4719)""",
    """\s+Account Name:\s+({user}.+?)\s+Account Domain""",
    """\s+Account Domain:\s+({domain}[^\s]+)""",
    """\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """\s+Category:\s+({audit_category}.+?)\s+Subcategory:""",
    """\s+Subcategory:\s+({subcategory}.+?)\s+Subcategory GUID:""",
    """\s+Changes:\s+({policy}.+?)\s+\d+"""
  ]
  DupFields = [ "host->dest_host" ]
}
```