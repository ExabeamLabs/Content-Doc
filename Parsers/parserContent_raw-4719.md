#### Parser Content
```Java
{
Name = raw-4719
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "4719", "System audit policy was changed" ]
  Fields = [
    """({event_name}System audit policy was changed)""",
    """\s({host}[^\s]+)\sMSWinEventLog""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
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