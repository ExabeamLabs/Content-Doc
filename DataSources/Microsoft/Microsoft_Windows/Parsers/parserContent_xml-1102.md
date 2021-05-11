#### Parser Content
```Java
{
Name = xml-1102
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = ["The audit log was cleared", "<EventID>1102" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\d\d\dZ)"""
    """\s{1,100}Logon ID:\s{1,100}({logon_id}[^<>\s=]+)""",
    """<Computer>({host}[^<]+?)<\/Computer>""",
    """Security ID:\s{0,100}({user_sid}[^\s:]+)""",
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
    """\s{1,100}Account Name:\s{1,100}({user}.+?)\s{1,100}Domain""",
    """\s{1,100}Domain Name:\s{1,100}({domain}[^\s]+)""",
    """\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]+)""",
  ]

```