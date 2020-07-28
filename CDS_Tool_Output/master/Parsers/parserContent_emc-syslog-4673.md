#### Parser Content
```Java
{
Name = emc-syslog-4673
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "__li_source_path=", "A privileged service was called","""eventid="4673"""" ]
  Fields = [
    """({event_name}A privileged service was called)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """__li_source_path="({host}[^"]+)"""",
    """({event_code}4673)""",
    """(K|k)eywords="({outcome}[^"]+)"""",
    """Process Name:\s+(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))\s+Service""",
    """\s+Account Domain:\s+({domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """(?:Information|Success Audit|Audit Success).+?Account Name:\s+({user}.+?)\s+Account Domain:""",
    """Server:\s+({object_server}.+?)\s+Service Name""",
    """Privileges:\s+({privileges}.+?)(,\d+|\s*$)""",
    """\s+({ownership_privilege}SeTakeOwnershipPrivilege)""",
    """\s+({environment_privilege}SeSystemEnvironmentPrivilege)""",
    """\s+({debug_privilege}SeDebugPrivilege)""",
    """\s+({tcb_privilege}SeTcbPrivilege)"""
  ]
  DupFields = [ "host->dest_ip","directory->process_directory" ]
}
```