#### Parser Content
```Java
{
Name = snare-612
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "\t612\t", "Audit Policy Change:" ]
  Fields = [
    """({event_name}Audit Policy Change)""",
    """\s{1,100}(Information|Audit Success|Success Audit)\s{1,100}({host}[\w.\-]{1,2000})""",
    """\s{1,100}(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})\s{1,100}""",
    """({event_code}612)""",
    """\s{1,100}User Name:\s{1,100}({user}.+?)\s{1,100}Domain""",
    """\s{1,100}Domain Name:\s{1,100}({domain}[^\s]{1,2000})""",
    """\s{1,100}Logon ID:\s{1,100}\([^,]{1,2000}
```