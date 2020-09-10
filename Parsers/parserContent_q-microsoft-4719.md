#### Parser Content
```Java
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