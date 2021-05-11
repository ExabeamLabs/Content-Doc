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
    """Logon Type:\s{0,100}({logon_type}[\d]+)""",
    """New Logon.*Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain:\s{1,100}({domain}[\w.\-]+)""",
    """Process Name:\s{1,100}(?:-|({process}[\w:\\.\-]+))""",
    """Source Network Address:\s{1,100}(?:-|({src_ip}[\w:.]+))\s{1,100}Source Port:""",
    """Logon Process:\s{0,100}({auth_process}[^\s]+)\s{1,100}Authentication Package:\s{0,100}({auth_package}[^\s]+)""",
    """Logon ID:\s{1,100}({logon_id}[^\s]+)\s{1,100}Logon GUID""",
    """New Logon:\s{1,100}Security ID:\s{1,100}({user_sid}[^\s]+)\s""",
    """Workstation Name:\s{1,100}([A-Fa-f:\d.]+|({src_host_windows}[^\s]+))\s{1,100}Source Network"""
  ]
  DupFields = [ "host->dest_ip" ]
}
```