#### Parser Content
```Java
{
Name = raw-4624
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4624"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["An account was successfully logged on", "Account Name"]
    Fields = [
      """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
      """({event_name}An account was successfully logged on)""",
      """TimeGenerated:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success)( |_)(success|audit)))\s*(\s|\t|,|#\d+|<[^>]+>)\s*({host}[^=]+?)\s*(\s|\t|,|#\d+|<[^>]+>)\s*""",
      """({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4624\)""",
      """"dhn":"({host}[^-"]+)""",
      """<Computer>({host}[^<]+)</Computer>""",
      """Computer(_name)?(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\||\s|;)""",
      """({event_code}4624)""",
      """Logon Type(:|=)\s*({logon_type}[\d]+)""",
      """New Logon.*?Account Name(:|=)\s*({user}.+?)[\s;]*Account Domain(:|=)\s*({domain}.+?)[\s;]*Logon ID(:|=)""",
      """Process Name(:|=)\s*(?:-|({process}({directory}.*?)(\\+({process_name}[^\\]+?))?))\s+Network Information:""",
      """Workstation Name(:|=)\s*(-|[A-Fa-f:\d.]+|({src_host_windows}[^\s;]+))[\s;]*Source Network Address(:|=)""",
      """Source Network Address(:|=)\s*(?:-|({src_ip}[\w:.]+))[\s;]*Source Port(:|=)""",
      """Logon Process(:|=)\s*({auth_process}[^\s;]+)[\s;]*Authentication Package(:|=)\s*({auth_package}[^\s;]+)""",
      """Logon ID(:|=)\s*({logon_id}[^\s;]+)[\s;]*(Linked Logon|Logon GUID)""",
      """New Logon(:|=)[\s;]*Security ID(:|=)\s*({user_sid}[^\s;]+)(\s|;)"""
    ]
    DupFields = ["host->dest_host", "directory->process_directory"]
  }
```