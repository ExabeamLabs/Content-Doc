#### Parser Content
```Java
{
Name = snare-517
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "\t517\t", "The audit log was cleared" ]
  Fields = [
    """({event_name}The audit log was cleared)""",
    """\s{1,100}(Information|Audit Success|Success Audit)\s{1,100}({host}[\w.\-]{1,2000})""",
    """\s{1,100}(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})\s{1,100}""",
    """({event_code}517)""",
    """({event_name}The audit log was cleared)""",
    """\s{1,100}Client User Name:\s{1,100}({user}.+?)\s{1,100}Client Domain""",
    """\s{1,100}Client Domain:\s{1,100}({domain}[^\s]{1,2000})""",
    """\s{1,100}Client Logon ID:\s{1,100}\([^,]{1,2000

}
```