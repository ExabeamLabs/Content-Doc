#### Parser Content
```Java
{
Name = emc-syslog-4674
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "__li_source_path=", "An operation was attempted on a privileged object","""eventid="4674"""" ]
  Fields = [
    """({event_name}An operation was attempted on a privileged object)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """__li_source_path="({host}[^"]{1,2000})"""",
    """({event_code}4674)""",
    """(K|k)eywords="({outcome}[^"]{1,2000})"""",
    """Process Name:\s{1,100}(?: |({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?)))\s{1,100}Requested""",
    """(?:Information|Success Audit|Audit Success).+?Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain:""",
    """\s{1,100}Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """Object Server:\s{1,100}({object_server}.+?)\s{1,100}Object Type:\s{1,100}(?:-|({object_type}.+?))\s{1,100}Object Name:\s{1,100}(?:-|({object}.+?))\s{1,100}Object Handle""",
    """Desired Access:\s{1,100}({accesses}.+?)\s{1,100}Privileges:\s{1,100}({privileges}.+?)(,\d{1,100}|\s{0,100}$)""",
    """\s{1,100}({ownership_privilege}SeTakeOwnershipPrivilege)""",
    """\s{1,100}({environment_privilege}SeSystemEnvironmentPrivilege)""",
    """\s{1,100}({debug_privilege}SeDebugPrivilege)""",
    """\s{1,100}({tcb_privilege}SeTcbPrivilege)"""
  ]
  DupFields = [ "host->dest_ip","directory->process_directory" ]
}
```