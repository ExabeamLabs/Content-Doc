#### Parser Content
```Java
{
Name = snare-578
  Vendor = Microsoft
  Product = Windows
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
    """\s{1,100}Primary Logon ID:\s{1,100}\([^,]{1,2000},({logon_id}[^)]{1,2000})""",
    """\s{1,100}Object Server:\s{1,100}(?:-|({object_server}.+?))\s{1,100}Object Handle""",
    """\s{1,100}Privileges:\s{1,100}({privileges}.+?)\s{1,100}\d{1,100}""",
    """\s{1,100}({ownership_privilege}SeTakeOwnershipPrivilege)""",
    """\s{1,100}({environment_privilege}SeSystemEnvironmentPrivilege)""",
    """\s{1,100}({debug_privilege}SeDebugPrivilege)""",
    """\s{1,100}({tcb_privilege}SeTcbPrivilege)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```