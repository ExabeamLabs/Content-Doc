#### Parser Content
```Java
{
Name = raw-1102
  Lms = Splunk
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "1102", "The audit log was cleared", "MSWinEventLog" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """\s+(Information|Audit Success|Success Audit)\s+({host}[\w.\-]+)""",
    """\s+({time}\w+\s+\d+\s+\d\d:\d\d:\d\d\s+\d\d\d\d)\s+""",
  ]
}

{
  Name = q-microsoft-4719
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-audit"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventIDCode=4719", "System audit policy was changed" ]
  Fields = [
    """({event_name}System audit policy was changed)""",
    """TimeGenerated=({time}\d+)""",
    """EventIDCode=({event_code}\d+)""",
    """\s+Account Name:\s+(({domain}[^\\]+)\\+)?({user}[^\s\\]+)\s+Account Domain""",
    """\s+Account Domain:\s+({domain}[^\s]+)""",
    """\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """\s+Category:\s+({audit_category}.+?)\s+Subcategory:""",
    """\s+Subcategory:\s+({subcategory}.+?)\s+Subcategory GUID:""",
    """\s+Changes:\s+({policy}.+?)\s*(\w+:|$)""",
    """\s+Computer=({host}[\w.\-]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```