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
      """__li_source_path="({host}[^"]+)"""",
    """({event_code}4674)""",
    """(K|k)eywords="({outcome}[^"]+)"""",
    """Process Name:\s+(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))\s+Requested""",
    """(?:Information|Success Audit|Audit Success).+?Account Name:\s+({user}.+?)\s+Account Domain:""",
    """\s+Account Domain:\s+({domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """Object Server:\s+({object_server}.+?)\s+Object Type:\s+(?:-|({object_type}.+?))\s+Object Name:\s+(?:-|({object}.+?))\s+Object Handle""",
    """Desired Access:\s+({accesses}.+?)\s+Privileges:\s+({privileges}.+?)(,\d+|\s*$)""",
    """\s+({ownership_privilege}SeTakeOwnershipPrivilege)""",
    """\s+({environment_privilege}SeSystemEnvironmentPrivilege)""",
    """\s+({debug_privilege}SeDebugPrivilege)""",
    """\s+({tcb_privilege}SeTcbPrivilege)"""
  ]
  DupFields = [ "host->dest_ip","directory->process_directory" ]
}
```