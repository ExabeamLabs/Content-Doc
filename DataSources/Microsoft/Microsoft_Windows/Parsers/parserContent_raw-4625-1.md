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
      """\s{0,100}Subject(:|=).+?Account Name(:|=)\s{0,100}(-|({caller_user}[^\s@]+?))[\s;]*Account Domain(:|=)""",
      """\s{0,100}Subject(:|=).+?Account Domain(:|=)\s{0,100}(-|({caller_domain}[^:;]+?))[\s;]*Logon ID(:|=)""",
      """\s{0,100}Logon Type(:|=)\s{0,100}({logon_type}[\d]+)""",
      """\s{0,100}Account For[\s;]*Which Logon Failed(:|=)[\s;]*Security ID(:|=)\s{0,100}(?:\/?NULL SID|({user_sid}.+?))[\s;]*Account Name""",
      """\s{0,100}Logon Failed(:|=).+?Account Name(:|=)\s{0,100}({user}[^\s@;]+?)[\s;]*Account Domain(:|=)""",
      """\s{0,100}Logon Failed(:|=).+?Account Name(:|=)\s{0,100}({user_email}[^\s@;]+?@[^\s@;]+?)[\s;]*Account Domain(:|=)""",
      """\s{0,100}Logon Failed(:|=).+?Account Domain(:|=)\s{0,100}(|-|({domain}[^\s]+?))[\s;]*Failure Information""",
      """\s{0,100}Sub Status(:|=)\s{0,100}({result_code}.+?)[\s;]*Process Information(:|=)""",
      """\s{0,100}Workstation Name(:|=)\s{0,100}(?:-|({src_host_windows}[^\s;]+))[\s;]*Source Network Address(:|=)""",
      """\s{0,100}Workstation Name(:|=)\s{0,100}(?:-|({src_host}[^\s;]+))[\s;]*Source Network Address(:|=)""",
      """\s{0,100}Source Network Address(:|=)\s{0,100}(?:-|({src_ip}[^\s;]+))[\s;]*Source Port(:|=)""",
      """\s{0,100}Logon Process(:|=)\s{0,100}({auth_process}[^\s;]+)[\s;]*Authentication Package(:|=)""",
      """\s{0,100}Authentication Package(:|=)\s{0,100}({auth_package}.+?)[\s;]*Transited Services(:|=)"""
      """\s{0,100}Key Length(:|=)\s{0,100}({key_length}\d{1,100})\s""",
      """\s{0,100}Subject(:|=)[\s;]*Security ID(:|=)\s{0,100}({subject_sid}[^;:=]+?)(\s{1,100}|;)Account Name(:|=)"""
    ]
    DupFields = ["host->dest_host"]
  }
```