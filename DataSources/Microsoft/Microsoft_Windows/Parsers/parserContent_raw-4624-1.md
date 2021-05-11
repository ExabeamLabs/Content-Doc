#### Parser Content
```Java
{
Name = raw-4624-1
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4624"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["An account was successfully logged on", "Account Name", "TimeGenerated:", "dhn"]
    Fields = [
      """({event_name}An account was successfully logged on)""",
      """TimeGenerated:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"dhn":"({host}[^-"]+)""",
      """({event_code}4624)""",
      """Logon Type(:|=)\s{0,100}({logon_type}[\d]+)""",
      """New Logon.*?Account Name(:|=)\s{0,100}(-|SYSTEM|({user}[^\s]+?))[\s;]*Account Domain(:|=)""",
      """New Logon.*?Account Domain(:|=)\s{0,100}(-|({domain}[^\s]+?))[\s;]*Logon ID(:|=)""",
      """Process Name(:|=)\s{0,100}(?:-|({process}({directory}.*?)(\\+({process_name}[^\\]+?))?))\s{1,100}Network Information:""",
      """Workstation Name(:|=)\s{0,100}(-|[A-Fa-f:\d.]+|({src_host_windows}[^\s;]+))[\s;]*Source Network Address(:|=)""",
      """Source Network Address(:|=)\s{0,100}(?:-|({src_ip}[\w:.]+))[\s;]*Source Port(:|=)""",
      """Logon Process(:|=)\s{0,100}({auth_process}[^\s;]+)[\s;]*Authentication Package(:|=)\s{0,100}({auth_package}[^\s;]+)""",
      """Logon ID(:|=)\s{0,100}({logon_id}[^\s;]+)[\s;]*(Linked Logon|Logon GUID)""",
      """New Logon(:|=)[\s;]*Security ID(:|=)\s{0,100}({user_sid}[^\s;]+)(\s|;)"""
    ]
    DupFields = ["host->dest_host", "directory->process_directory"]
  }
```