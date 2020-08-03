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
  Fields = [ """exabeam_host=({host}[^\s]+)""",
    """({event_name}Privileged object operation)""",
    """\s+(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)\s+""",
    """\s+(Information|Audit Success|Success Audit)\s+({host}[^\s]+)""",
    """(?:Information|Audit Success|Success Audit).+?Primary User Name:\s+({user}.+?)\s+Primary Domain""",
    """({event_code}578)""",
    """Security\t([^\s]+\t){2}({outcome}.+?)\t""",
    """\s+Primary Domain:\s+({domain}[^\s]+)""",
    """\s+Primary Logon ID:\s+\([^,]+,({logon_id}[^)]+)""",
    """\s+Object Server:\s+(?:-|({object_server}.+?))\s+Object Handle""",
    """\s+Privileges:\s+({privileges}.+?)\s+\d+""",
    """\s+({ownership_privilege}SeTakeOwnershipPrivilege)""",
    """\s+({environment_privilege}SeSystemEnvironmentPrivilege)""",
    """\s+({debug_privilege}SeDebugPrivilege)""",
    """\s+({tcb_privilege}SeTcbPrivilege)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```