#### Parser Content
```Java
{
Name = xml-1102
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = ["The audit log was cleared", "<EventID>1102" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\d\d\dZ)"""
    """\s+Logon ID:\s+({logon_id}[^<]+)"""
  ]
}


${WinParserTemplates.raw-1102} {
  Name = raw-1102
  Lms = Splunk
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = ["The audit log was cleared" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """\s+(Information|Audit Success|Success Audit)\s+({host}[\w.\-]+)""",
    """\s+({time}\w+\s+\d+\s+\d\d:\d\d:\d\d\s+\d\d\d\d)\s+""",
  ]
  DupFields = [ "host->dest_host" ]
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