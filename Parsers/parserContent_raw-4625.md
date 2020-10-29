#### Parser Content
```Java
{
Name = raw-4625
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    Conditions = ["An account failed to log on", "Failure Reason"]
    Fields = [
      """({event_name}An account failed to log on)""",
      """({event_code}4625)""",
      """timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""""
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
      """Audit\s({host}[\w\-.]+)\s+""",
      """({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+)""",
      """\w+\s*\d+\s*\d+:\d+:\d+\s+(::ffff:)?({host}[\w\-.]+)""",
      """Subject(:|=).+?Account Name(:|=)\s*(-|({caller_user}[^\s@]+?))[\s;]*Account Domain(:|=)""",
      """Subject(:|=).+?Account Domain(:|=)\s*(-|({caller_domain}[^:;]+?))[\s;]*Logon ID(:|=)""",
      """Logon Type(:|=)\s*({logon_type}[\d]+)""",
      """Account For[\s;]*Which Logon Failed(:|=)[\s;]*Security ID(:|=)\s*(?:\/?NULL SID|({user_sid}.+?))[\s;]*Account Name""",
      """Logon Failed(:|=).+?Account Name(:|=)\s*(-|\++|SYSTEM|d2\/|({user}[^\s@]+?))[\s;]*Account Domain(:|=)""",
      """Logon Failed(:|=).+?Account Name(:|=)\s*({user_email}[^\s@;]+?@[^\s@;]+?)[\s;]*Account Domain(:|=)""",
      """Logon Failed(:|=).+?Account Domain(:|=)\s*(|-|\?|({domain}[^\s]+?))[\s;]*Failure Information""",
      """Sub Status(:|=)\s*({result_code}.+?)[\s;]*Process Information(:|=)""",
      """Workstation Name(:|=)\s*(?:-|({src_host_windows}[^\s;]+))[\s;]*Source Network Address(:|=)""",
      """Source Network Address(:|=)\s*(?:-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))[\s;]*Source Port(:|=)""",
      """Logon Process(:|=)\s*({auth_process}[^\s;]+)[\s;]*Authentication Package(:|=)""",
      """Authentication Package(:|=)\s*({auth_package}.+?)[\s;]*Transited Services(:|=)""",
      """\s({event_code}4625)\s""",
      """\w+\s*\d+\s*\d+:\d+:\d+\s+(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))"""
    ]
    DupFields = ["src_host_windows->src_host"]
  }
```