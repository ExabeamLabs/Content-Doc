#### Parser Content
```Java
{
Name = raw-4625-1
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-failed-logon"
    TimeFormat = "MM/dd/yyyy HH:mm:ss"
    Conditions = ["An account failed to log on", "Failure Reason", "Computer"]
    Fields = [
      """({event_name}An account failed to log on)""",
      """({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d)""",
      """ComputerName=({host}[^\s;]+)""",
      """({event_code}4625)""",
      """\s*Subject(:|=).+?Account Name(:|=)\s*(-|({caller_user}[^\s@]+?))[\s;]*Account Domain(:|=)""",
      """\s*Subject(:|=).+?Account Domain(:|=)\s*(-|({caller_domain}[^:;]+?))[\s;]*Logon ID(:|=)""",
      """\s*Logon Type(:|=)\s*({logon_type}[\d]+)""",
      """\s*Account For[\s;]*Which Logon Failed(:|=)[\s;]*Security ID(:|=)\s*(?:\/?NULL SID|({user_sid}.+?))[\s;]*Account Name""",
      """\s*Logon Failed(:|=).+?Account Name(:|=)\s*({user}[^\s@;]+?)[\s;]*Account Domain(:|=)""",
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