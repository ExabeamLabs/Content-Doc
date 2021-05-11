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
      """({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
      """Audit\s(::ffff:)?({host}[\w\-.]+)\s{1,100}""",
      """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100})""",
      """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(am|pm|({host}[\w\-.]+))""",
      """Subject(:|=).+?Account Name(:|=)\s{0,100}(-|({caller_user}[^\s@]+?))[\s;]*Account Domain(:|=)""",
      """Subject(:|=).+?Account Domain(:|=)\s{0,100}(-|({caller_domain}[^:;]+?))[\s;]*Logon ID(:|=)""",
      """Logon Type(:|=)\s{0,100}({logon_type}[\d]+)""",
      """Account For[\s;]*Which Logon Failed(:|=)[\s;]*Security ID(:|=)\s{0,100}(?:\/?NULL SID|({user_sid}.+?))[\s;]*Account Name""",
      """Logon Failed(:|=).+?Account Name(:|=)\s{0,100}(-|\++|SYSTEM|d2\/|({user}[^\s@]+?))[\s;]*Account Domain(:|=)""",
      """Logon Failed(:|=).+?Account Name(:|=)\s{0,100}({user_email}[^\s@;]+?@[^\s@;]+?)[\s;]*Account Domain(:|=)""",
      """Logon Failed(:|=).+?Account Domain(:|=)\s{0,100}(|-|\?|({domain}[^\s]+?))[\s;]*Failure Information""",
      """Sub Status(:|=)\s{0,100}({result_code}.+?)[\s;]*Process Information(:|=)""",
      """Workstation Name(:|=)\s{0,100}(?:-|(::ffff:)?({src_host_windows}[^\s;]+))[\s;]*Source Network Address(:|=)""",
      """Source Network Address(:|=)\s{0,100}(?:-|(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))[\s;]*Source Port(:|=)""",
      """Logon Process(:|=)\s{0,100}({auth_process}[^\s;]+)[\s;]*Authentication Package(:|=)""",
      """Authentication Package(:|=)\s{0,100}({auth_package}.+?)[\s;]*Transited Services(:|=)""",
      """\s({event_code}4625)\s""",
      """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|({dest_host}[\w\-.]+)))"""
    ]
    DupFields = ["host->dest_host","src_host_windows->src_host"]
  }
```