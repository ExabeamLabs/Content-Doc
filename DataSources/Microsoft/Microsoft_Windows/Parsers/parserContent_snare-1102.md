#### Parser Content
```Java
{
Name = snare-1102
  Lms = Splunk
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "\t1102\t", "The audit log was cleared" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """\s+(Information|Audit Success|Success Audit)\s+({host}[\w.\-]+)""",
    """\s+({time}\w+\s+\d+\s+\d\d:\d\d:\d\d\s+\d\d\d\d)\s+""",
  ]
}
raw-1102 = {
  Vendor = Microsoft
  Product = Microsoft Windows
  DataType = "windows-audit"
  Fields = [
    """({event_code}1102)""",
    """({event_name}The audit log was cleared)""",
    """\s+Account Name:\s+({user}.+?)\s+Domain""",
    """\s+Domain Name:\s+({domain}[^\s]+)""",
    """\s+Logon ID:\s+({logon_id}[^\s]+)"""
  ]

```