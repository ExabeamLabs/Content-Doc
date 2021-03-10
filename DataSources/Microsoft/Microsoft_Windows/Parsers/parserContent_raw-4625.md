#### Parser Content
```Java
{
Name = raw-4625
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-failed-logon"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["An account failed to log on", "Failure Reason"]
    Fields = [
      """({event_name}An account failed to log on)""",
      """({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+""",
      """Computer(Name|_name)?\s*\\*"?(=|:|>)\s*"*({host}[\w\.-]+)(\s|,|"|<\/Computer>|$)""",
      """({event_code}4625)""",
      """\s*Subject(:|=).+?Account Name(:|=)\s*(-|({caller_user}[^\s@]+?))[\s;]*Account Domain(:|=)""",
      """\s*Subject(:|=).+?Account Domain(:|=)\s*(-|({caller_domain}[^:;]+?))[\s;]*Logon ID(:|=)""",
      """\s*Logon Type(:|=)\s*({logon_type}[\d]+)""",
      """\s*Account For[\s;]*Which Logon Failed(:|=)[\s;]*Security ID(:|=)\s*(?:\/?NULL SID|({user_sid}.+?))[\s;]*Account Name""",
      """\s*Logon Failed(:|=).+?Account Name(:|=)\s*({user}[^\s@]+?)[\s;]*Account Domain(:|=)""",
      """\s*Logon Failed(:|=).+?Account Name(:|=)\s*({user_email}[^\s@;]+?@[^\s@;]+?)[\s;]*Account Domain(:|=)""",
      """\s*Logon Failed(:|=).+?Account Domain(:|=)\s*(|-|({domain}[^\s]+?))[\s;]*Failure Information""",
      """\s*Sub Status(:|=)\s*({result_code}.+?)[\s;]*Process Information(:|=)""",
      """\s*Workstation Name(:|=)\s*(?:-|({src_host_windows}[^\s;]+))[\s;]*Source Network Address(:|=)""",
      """\s*Workstation Name(:|=)\s*(?:-|({src_host}[^\s;]+))[\s;]*Source Network Address(:|=)""",
      """\s*Source Network Address(:|=)\s*(?:-|({src_ip}[^\s;]+))[\s;]*Source Port(:|=)""",
      """\s*Logon Process(:|=)\s*({auth_process}[^\s;]+)[\s;]*Authentication Package(:|=)""",
      """\s*Authentication Package(:|=)\s*({auth_package}.+?)[\s;]*Transited Services(:|=)"""
    ]
    DupFields = ["host->dest_host"]
  }
```