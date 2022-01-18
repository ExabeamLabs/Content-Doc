#### Parser Content
```Java
{
Name = snare-576
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-privileged-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "\t576\t", "Special privileges assigned to new logon:" ]
  Fields = [ """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({event_name}Special privileges assigned to new logon)""",
    """\s{1,100}(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})\s{1,100}""",
    """({event_code}576)""",
    """Security\t([^\s]{1,2000}\t){2}({outcome}.+?)\t""",
    """(?:Information|Audit Success|Success Audit).+?User Name:\s{1,100}({user}.+?)\s{1,100}Domain""",
    """\s{1,100}Domain:\s{1,100}({domain}[^\s]{1,2000})""",
    """\s{1,100}Logon ID:\s{1,100}\([^,]{1,2000

}
```