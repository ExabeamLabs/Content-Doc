#### Parser Content
```Java
{
Name = s-1102
  Lms = Splunk
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """EventCode=1102""", "The audit log was cleared" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """\sComputerName=({host}[\w.\-]+)""",
    """({time}\d\d/\d\d/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))\s{1,100}"""
  ]
  DupFields = [ "host->dest_host" ]
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