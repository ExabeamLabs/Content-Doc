#### Parser Content
```Java
{
Name = raw-4624-7
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4624"
    TimeFormat = "yyyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["An account was successfully logged on", "Account Name", "Microsoft-Windows-Security-Auditing"]
    Fields = [
      """({event_name}An account was successfully logged on)""",
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
      """Computer(Name)?="?({host}[^\s"]+)""",
      """({event_code}4624)""",
      """Logon Type(:|=)\s{0,100}({logon_type}[\d]+)""",
      """New Logon[^"]*?Account Name(:|=)\s{0,100}(-|SYSTEM|({user}[^\s]+))""",
      """New Logon[^"]*?Account Domain(:|=)\s{0,100}(-|NT AUTHORITY|({domain}[^\s]+))""",
      """Process Name(:|=)\s{0,100}(?:-|({process}({directory}[^=]*?)(\\+({process_name}[^\\]+?))?))\s{1,100}Network Information:""",
      """Workstation Name(:|=)\s{0,100}(-|[A-Fa-f:\d.]+|(::ffff:)?({src_host_windows}[^\s;]+))[\s;]*Source Network Address(:|=)""",
      """Source Network Address(:|=)\s{0,100}(?:-|(::ffff:)?({src_ip}[a-fA-F\d.:]+))[\s;]*Source Port(:|=)""",
      """Logon Process(:|=)\s{0,100}({auth_process}[^\s;]+)[\s;]*Authentication Package(:|=)\s{0,100}({auth_package}[^\s;]+)""",
      """Logon ID(:|=)\s{0,100}({logon_id}[^\s;]+)""", 
      """New Logon(:|=)[\s;]*Security ID(:|=)\s{0,100}(NT AUTHORITY\\SYSTEM|({user_sid}[^;:=]+?))[\s;]*Account Name(:|=)""",
      """:\d{1,100}:\d{1,100}\s{1,100}(\d\d\d\d|((?i)AM|PM)|(::ffff:)?(({dest_ip}[a-fA-F0-9.:]+)|({dest_host}[\w\-.]+)))\s""",
      """:\d{1,100}\.\d{1,100}(\+|-)\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}[a-fA-F0-9.:]+)|({dest_host}[\w\-.]+))\s"""
      """Key Length(:|=)\s{0,100}({key_length}\d{1,100})"""
      """Subject(:|=)[\s;]*Security ID(:|=)\s{0,100}({subject_sid}[^;:=]+?)(\s{1,100}|;)Account Name(:|=)"""
    ]
    DupFields = [ "directory->process_directory" ]
  }
```