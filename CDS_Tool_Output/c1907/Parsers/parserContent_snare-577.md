#### Parser Content
```Java
{
Name = snare-577
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-privileged-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "\t577\t", "Privileged Service Called:" ]
  Fields = [ """exabeam_host=({host}[^\s]+)""",
    """({event_name}Privileged Service Called)""",
    """\s+(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)\s+""",
    """\s+(Information|Audit Success|Success Audit)\s+({host}[^\s]+)""",
    """({event_code}577)""",
    """Security\t([^\s]+\t){2}({outcome}.+?)\t""",
    """(?:Information|Audit Success|Success Audit).+?Primary User Name:\s+({user}.+?)\s+Primary Domain""",
    """\s+Primary Domain:\s+({domain}[^\s]+)""",
    """\s+Primary Logon ID:\s+\([^,]+,({logon_id}[^)]+)""",
    """\s+Privileges:\s+({privileges}.+?)\s+\d+""",
    """\s+({ownership_privilege}SeTakeOwnershipPrivilege)""",
    """\s+({environment_privilege}SeSystemEnvironmentPrivilege)""",
    """\s+({debug_privilege}SeDebugPrivilege)""",
    """\s+({tcb_privilege}SeTcbPrivilege)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```