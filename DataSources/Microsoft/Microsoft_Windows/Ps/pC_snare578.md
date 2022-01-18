#### Parser Content
```Java
{
Name = snare-578
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-privileged-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "\t578\t", "Privileged object operation:" ]
  Fields = [ """exabeam_host=({host}[^\s]{1,2000})""",
    """({event_name}Privileged object operation)""",
    """\s{1,100}(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})\s{1,100}""",
    """\s{1,100}(Information|Audit Success|Success Audit)\s{1,100}({host}[^\s]{1,2000})""",
    """(?:Information|Audit Success|Success Audit).+?Primary User Name:\s{1,100}({user}.+?)\s{1,100}Primary Domain""",
    """({event_code}578)""",
    """Security\t([^\s]{1,2000}\t){2}({outcome}.+?)\t""",
    """\s{1,100}Primary Domain:\s{1,100}({domain}[^\s]{1,2000})""",
    """\s{1,100}Primary Logon ID:\s{1,100}\([^,]{1,2000

}
```