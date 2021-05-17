#### Parser Content
```Java
{
Name = raw-4624-2
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4624"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["An account was successfully logged on", "Account Name", "TimeGenerated:", "Microsoft-Windows-Security-Auditing"]
    Fields = [
      """({event_name}An account was successfully logged on)""",
      """TimeGenerated:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({host}[^\s\/]{1,2000})\/Microsoft-Windows-Security-Auditing \(4624\)""",
      """({event_code}4624)""",
      """Logon Type(:|=)\s{0,100}({logon_type}[\d]{1,2000})""",
      """New Logon.*?Account Name(:|=)\s{0,100}(-|SYSTEM|({user}[^\s]{1,2000}?))[\s;]{0,2000}Account Domain(:|=)""",
      """New Logon.*?Account Domain(:|=)\s{0,100}(-|({domain}[^\s]{1,2000}?))[\s;]{0,2000}Logon ID(:|=)""",
      """Process Name(:|=)\s{0,100}(?:-|({process}({directory}.*?)(\\+({process_name}[^\\]{1,2000}?))?))\s{1,100}Network Information:""",
      """Workstation Name(:|=)\s{0,100}(-|[A-Fa-f:\d.]{1,2000}|({src_host_windows}[^\s;]{1,2000}))[\s;]{0,2000}Source Network Address(:|=)""",
      """Source Network Address(:|=)\s{0,100}(?:-|({src_ip}[\w:.]{1,2000}))[\s;]{0,2000}Source Port(:|=)""",
      """Logon Process(:|=)\s{0,100}({auth_process}[^\s;]{1,2000})[\s;]{0,2000}Authentication Package(:|=)\s{0,100}({auth_package}[^\s;]{1,2000})""",
      """Logon ID(:|=)\s{0,100}({logon_id}[^\s;]{1,2000})[\s;]{0,2000}(Linked Logon|Logon GUID)""",
      """New Logon(:|=)[\s;]{0,2000}Security ID(:|=)\s{0,100}({user_sid}[^\s;]{1,2000})(\s|;)"""
    ]
    DupFields = ["host->dest_host", "directory->process_directory"]
  }
```