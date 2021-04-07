#### Parser Content
```Java
{
Name = s-4719
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "EventCode=4719", "System audit policy was changed" ]
  Fields = [
    """({event_name}System audit policy was changed)""",
    """ComputerName=({host}[\w.\-]+)""",
    """({time}\d\d/\d\d/\d\d\d\d \d+:\d+:\d+ (am|AM|pm|PM))\s+""",
    """EventCode=({event_code}\d+)""",
    """\s+Account Name:\s+({user}.+?)\s+Account Domain""",
    """\s+Account Domain:\s+({domain}[^\s]+)""",
    """\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """\s+Category:\s+({audit_category}.+?)\s+Subcategory:""",
    """\s+Subcategory:\s+({subcategory}.+?)\s+Subcategory GUID:""",
    """\s+Changes:\s+({policy}[^:]+?)(\s+\d+|\s*$)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```