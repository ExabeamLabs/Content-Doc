#### Parser Content
```Java
{
Name = emc-syslog-4672
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "__li_source_path=", "Special privileges assigned to new logon","""eventid="4672"""" ]
  Fields = [ 
    """({event_name}Special privileges assigned to new logon)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """__li_source_path="({host}[^"]+)"""",
    """({event_code}4672)""",
    """(K|k)eywords="({outcome}[^"]+)"""",
    """(?:Information|Success Audit|Audit Success).+?Account Name:\s+({user}.+?)\s+Account Domain""",
    """\s+Account Domain:\s+({domain}[^\s]+)""",
    """\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """\s+Privileges:\s+({privileges}.+?)(,\d+|\s*$)""",
    """\s+({ownership_privilege}SeTakeOwnershipPrivilege)""",
    """\s+({environment_privilege}SeSystemEnvironmentPrivilege)""",
    """\s+({debug_privilege}SeDebugPrivilege)""",
    """\s+({tcb_privilege}SeTcbPrivilege)"""
  ]
  DupFields = [ "host->dest_ip" ]
}
```