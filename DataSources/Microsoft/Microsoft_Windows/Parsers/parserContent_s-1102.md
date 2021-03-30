#### Parser Content
```Java
{
Name = s-1102
  Lms = Splunk
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """EventCode=1102""", "The audit log was cleared" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """\sComputerName=({host}[\w.\-]+)""",
    """({time}\d\d/\d\d/\d\d\d\d \d+:\d+:\d+ (am|AM|pm|PM))\s+"""
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