#### Parser Content
```Java
{
Name = xml-4625-1
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
    Conditions = ["<EventID>4625</EventID>", "An account failed to log on", "Failure Reason", "Computer"]
    Fields = [
      """({event_name}An account failed to log on)""",
      """TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\d\d\dZ)'""",
      """Computer>({host}[^<]+)<\/Computer""",
      """({event_code}4625)""",
      """Subject(:|=).+?Account Name(:|=)\s{0,100}(-|({caller_user}[^\s@]+?))[\s;]*Account Domain(:|=)""",
      """Logon Type(:|=)\s{0,100}({logon_type}[\d]+)\s{1,100}Account\s""",
      """Account For[\s;]*Which Logon Failed(:|=)[\s;]*Security ID(:|=)\s{0,100}(?:\/?NULL SID|({user_sid}.+?))[\s;]*Account Name""",
      """Logon Failed(:|=).+?Account Name(:|=)\s{0,100}({user}[^\s@]+?)[\s;]*Account Domain(:|=)""",
      """Logon Failed(:|=).+?Account Name(:|=)\s{0,100}({user_email}[^\s@;]+?@[^\s@;]+?)[\s;]*Account Domain(:|=)""",
      """Logon Failed(:|=).+?Account Domain(?::|=)\s{0,100}(|-|({domain}[^\s]+?))[\s;]*Failure Information""",
      """Sub Status(:|=)\s{0,100}({result_code}.+?)[\s;]*Process Information(:|=)""",
      """Workstation Name(:|=)\s{0,100}(-|({src_host_windows}[^\s;]+))[\s;]*Source Network Address(:|=)""",
      """Source Network Address(:|=)\s{0,100}(-|({src_ip}[^\s;]+))[\s;]*Source Port(:|=)""",
      """Logon Process(:|=)\s{0,100}({auth_process}[^\s;]+)[\s;]*Authentication Package(:|=)""",
      """Authentication Package(:|=)\s{0,100}({auth_package}.+?)[\s;]*Transited Services(:|=)""",
    ]
    DupFields = ["host->dest_host", "src_host_windows->src_host"]
  }
```