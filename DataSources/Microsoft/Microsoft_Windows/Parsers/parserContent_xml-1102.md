#### Parser Content
```Java
{
Name = xml-1102
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = ["The audit log was cleared", "<EventID>1102" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\d\d\dZ)"""
    """\s+Logon ID:\s+({logon_id}[^<>\s=]+)""",
    """<Computer>({host}[^<]+?)<\/Computer>""",
    """Security ID:\s*({user_sid}[^\s:]+)""",
  ]
}
raw-1102 = {
  Vendor = Microsoft
  Product = Microsoft Windows
  DataType = "windows-audit"
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """({event_code}1102)""",
    """({event_name}The audit log was cleared)""",
    """\s+Account Name:\s+({user}.+?)\s+Domain""",
    """\s+Domain Name:\s+({domain}[^\s]+)""",
    """\s+Logon ID:\s+({logon_id}[^\s]+)""",
  ]

```