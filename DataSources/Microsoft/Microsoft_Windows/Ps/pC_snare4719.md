#### Parser Content
```Java
{
Name = snare-4719
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "\t4719\t", "System audit policy was changed" ]
  Fields = [
    """({event_name}System audit policy was changed)""",
    """\s{1,100}(Information|Audit Success|Success Audit)\s{1,100}({host}[\w.\-]{1,2000})""",
    """\s{1,100}(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})\s{1,100}""",
    """({event_code}4719)""",
    """\s{1,100}Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain""",
    """\s{1,100}Account Domain:\s{1,100}({domain}[^\s]{1,2000})""",
    """\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """\s{1,100}Category:\s{1,100}({audit_category}.+?)\s{1,100}Subcategory:""",
    """\s{1,100}Subcategory:\s{1,100}({subcategory}.+?)\s{1,100}Subcategory GUID:""",
    """\s{1,100}Changes:\s{1,100}({policy}.+?)\s{1,100}\d{1,100}"""
  ]
  DupFields = [ "host->dest_host" ]


}
```