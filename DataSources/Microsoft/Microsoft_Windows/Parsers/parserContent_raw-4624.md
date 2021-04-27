#### Parser Content
```Java
{
Name = raw-4624
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4624"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["An account was successfully logged on", "Account Name:"]
    Fields = [
      """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """(?i)<\d+>\s*\w+\s+\d+\s+\d+:\d+:\d+\s+(am|pm|({host}[\w.\-]+))""",
      """({event_name}An account was successfully logged on)""",
      """({event_code}4624)""",
      """Logon Type:\s*({logon_type}[\d]+)""",
      """New Logon.*?Account Name:\s*(-|SYSTEM|({user}[^\s]+?))[\s;]*Account Domain""",
      """New Logon.*?Account Domain:\s*(-|({domain}[^\s]+?))[\s;]*Logon ID""",
      """Process Name:\s*(?:-|({process}({directory}.*?)(\\+({process_name}[^\\]+?))?))\s+Network Information""",
      """Workstation Name:\s*(-|[A-Fa-f:\d.]+|({src_host_windows}[^\s;]+))[\s;]*Source Network Address""",
      """Source Network Address:\s*(?:-|({src_ip}[\w:.]+))[\s;]*Source Port""",
      """Logon Process:\s*({auth_process}[^\s;]+)[\s;]*Authentication Package:\s*({auth_package}[^\s;]+)""",
      """Logon ID:\s*({logon_id}[^\s;]+)[\s;]*(Linked Logon|Logon GUID)""",
      """New Logon:[\s;]*Security ID:\s*({user_sid}[^\s;]+)(\s|;)""",
    ]
    DupFields = ["host->dest_host", "directory->process_directory"]
  }
```