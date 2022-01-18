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
    """__li_source_path="({host}[^"]{1,2000})"""",
    """({event_code}4672)""",
    """(K|k)eywords="({outcome}[^"]{1,2000})"""",
    """(?:Information|Success Audit|Audit Success).+?Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain""",
    """\s{1,100}Account Domain:\s{1,100}({domain}[^\s]{1,2000})""",
    """\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """\s{1,100}Privileges:\s{1,100}({privileges}.+?)(,\d{1,100}|\s{0,100}$)""",
    """\s{1,100}({ownership_privilege}SeTakeOwnershipPrivilege)""",
    """\s{1,100}({environment_privilege}SeSystemEnvironmentPrivilege)""",
    """\s{1,100}({debug_privilege}SeDebugPrivilege)""",
    """\s{1,100}({tcb_privilege}SeTcbPrivilege)"""
  ]
  DupFields = [ "host->dest_ip" ]


}
```