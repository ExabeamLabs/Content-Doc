#### Parser Content
```Java
{
Name = raw-4624-8
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4624"
    TimeFormat = "MM/dd/yyy HH:mm:ss"
    Conditions = ["An account was successfully logged on", "Account Name", "Computer"]
    Fields = [
      """({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d)""",
      """({event_name}An account was successfully logged on)""",
      """ComputerName=({host}({dest_host}[\w\-]+)[^\s]*)\s""",
      """({event_code}4624)""",
      """Logon Type(:|=)\s*({logon_type}[\d]+)""",
      """New Logon[^\}]*?Account Name(:|=)\s*(-|SYSTEM|({user}[^\s]+?))[\s;]*Account Domain(:|=)""",
      """New Logon[^\}]*?Account Domain(:|=)\s*(-|({domain}[^\s]+?))[\s;]*Logon ID(:|=)""",
      """Process Name(:|=)\s*(?:-|({process}({directory}[^\}]*?)(\\+({process_name}[^\\]+?))?))\s+Network Information:""",
      """Workstation Name(:|=)\s*(-|[A-Fa-f:\d.]+|({src_host_windows}[^\s;]+))[\s;]*Source Network Address(:|=)""",
      """Source Network Address(:|=)\s*(?:-|({src_ip}[\w:.]+))[\s;]*Source Port(:|=)""",
      """Logon Process(:|=)\s*({auth_process}[^\s;]+)[\s;]*Authentication Package(:|=)\s*({auth_package}[^\s;]+)""",
      """Logon ID(:|=)\s*({logon_id}[^\s;]+)[\s;]*(Linked Logon|Logon GUID)""",
      """New Logon(:|=)[\s;]*Security ID(:|=)\s*(NT AUTHORITY\\+SYSTEM|({user_sid}[^;:=]+?))(\s+|;)Account Name(:|=)"""
      """Key Length(:|=)\s*({key_length}\d+)"""
      """Subject(:|=)[\s;]*Security ID(:|=)\s*({subject_sid}[^;:=]+?)(\s+|;)Account Name(:|=)"""
    ]
    DupFields = ["directory->process_directory"]
  }
```