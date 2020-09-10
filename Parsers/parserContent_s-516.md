#### Parser Content
```Java
{
Name = s-516
  DataType = "account-lockout"
  Conditions = [ """EventCode=516""", """Message=Internal resources allocated for the queuing of audit messages have been exhausted""" ]
}

${WinParserTemplates.windows-events} {
  Name = s-560
  DataType = "file-operations"
  Conditions = [ """EventCode=560""", """Message=Object Open""" ]
}

{
  Name = snare-576
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-privileged-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "\t576\t", "Special privileges assigned to new logon:" ]
  Fields = [ """exabeam_host=({host}[\w.\-]+)""",
    """({event_name}Special privileges assigned to new logon)""",
    """\s+(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)\s+""",
    """({event_code}576)""",
    """Security\t([^\s]+\t){2}({outcome}.+?)\t""",
    """(?:Information|Audit Success|Success Audit).+?User Name:\s+({user}.+?)\s+Domain""",
    """\s+Domain:\s+({domain}[^\s]+)""",
    """\s+Logon ID:\s+\([^,]+,({logon_id}[^)]+)""",
    """\s+Privileges:\s+({privileges}.+?)\s+\d+""",
    """\s+({ownership_privilege}SeTakeOwnershipPrivilege)""",
    """\s+({environment_privilege}SeSystemEnvironmentPrivilege)""",
    """\s+({debug_privilege}SeDebugPrivilege)""",
    """\s+({tcb_privilege}SeTcbPrivilege)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```