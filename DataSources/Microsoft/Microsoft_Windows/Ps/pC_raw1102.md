#### Parser Content
```Java
{
Name = raw-1102
  Lms = Splunk
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = ["The audit log was cleared" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """\s{1,100}(Information|Audit Success|Success Audit)\s{1,100}({host}[\w.\-]{1,2000})""",
    """\s{1,100}({time}\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}\d\d\d\d)\s{1,100}""",
  ]
  DupFields = [ "host->dest_host" ]

raw-1102 = {
  Vendor = Microsoft
  Product = Microsoft Windows
  DataType = "windows-audit"
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """({event_code}1102)""",
    """({event_name}The audit log was cleared)""",
    """\s{1,100}Account Name:\s{1,100}({user}.+?)\s{1,100}Domain""",
    """\s{1,100}Domain Name:\s{1,100}({domain}[^\s]{1,2000})""",
    """\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
  ]
  DupFields = [ "host->dest_host" 
}
```