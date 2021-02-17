#### Parser Content
```Java
{
Name = emc-syslog-4624
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4624"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "__li_source_path=", "An account was successfully logged on","""eventid="4624"""" ]
  Fields = [
    """({event_name}An account was successfully logged on)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """__li_source_path="({host}[^"]+)"""",
    """({event_code}4624)""",
    """Logon Type:\s*({logon_type}[\d]+)""",
    """New Logon.*Account Name:\s+({user}.+?)\s+Account Domain:\s+({domain}[\w.\-]+)""",
    """Process Name:\s+(?:-|({process}[\w:\\.\-]+))""",
    """Source Network Address:\s+(?:-|({src_ip}[\w:.]+))\s+Source Port:""",
    """Logon Process:\s*({auth_process}[^\s]+)\s+Authentication Package:\s*({auth_package}[^\s]+)""",
    """Logon ID:\s+({logon_id}[^\s]+)\s+Logon GUID""",
    """New Logon:\s+Security ID:\s+({user_sid}[^\s]+)\s""",
    """Workstation Name:\s+([A-Fa-f:\d.]+|({src_host_windows}[^\s]+))\s+Source Network"""
  ]
  DupFields = [ "host->dest_ip" ]
}
```