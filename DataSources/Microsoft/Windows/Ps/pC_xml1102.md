#### Parser Content
```Java
{
Name = xml-1102
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = ["The audit log was cleared", "<EventID>1102" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\d\d\dZ)"""
    """\s{1,100}Logon ID:\s{1,100}({logon_id}[^<>\s=]{1,2000})""",
    """<Computer>({host}[^<]{1,2000}?)<\/Computer>""",
    """Security ID:\s{0,100}({user_sid}[^\s:]{1,2000})""",
  ]

raw-1102 = {
  Vendor = Microsoft
  Product = Windows
  DataType = "windows-audit"
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """Hostname":"({host}[^"]{1,2000})"""",
    """({event_code}1102)""",
    """({event_name}The audit log was cleared)""",
    """\s{1,100}Account Name:\s{1,100}({user}[^:]{1,2000}?)\s{1,100}Domain""",
    """\s{1,100}Domain Name:\s{1,100}({domain}[^\s]{1,2000})""",
    """\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
  ]
  DupFields = [ "host->dest_host" 
}
```