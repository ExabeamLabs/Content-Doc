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
      """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
      """Computer(Name)?=({host}[^\s]+)""",
      """({event_code}4624)""",
      """Logon Type(:|=)\s*({logon_type}[\d]+)""",
      """New Logon[^"]*?Account Name(:|=)\s*(-|SYSTEM|({user}[^\s]+))""",
      """New Logon[^"]*?Account Domain(:|=)\s*(-|NT AUTHORITY|({domain}[^\s]+))""",
      """Process Name(:|=)\s*(?:-|({process}({directory}[^=]*?)(\\+({process_name}[^\\]+?))?))\s+Network Information:""",
      """Workstation Name(:|=)\s*(-|[A-Fa-f:\d.]+|(::ffff:)?({src_host_windows}[^\s;]+))[\s;]*Source Network Address(:|=)""",
      """Source Network Address(:|=)\s*(?:-|(::ffff:)?({src_ip}[a-fA-F\d.:]+))[\s;]*Source Port(:|=)""",
      """Logon Process(:|=)\s*({auth_process}[^\s;]+)[\s;]*Authentication Package(:|=)\s*({auth_package}[^\s;]+)""",
      """Logon ID(:|=)\s*({logon_id}[^\s;]+)""", 
      """New Logon(:|=)[\s;]*Security ID(:|=)\s*(NT AUTHORITY\\SYSTEM|({user_sid}[^;:=]+?))[\s;]*Account Name(:|=)""",
      """:\d+:\d+\s+(\d\d\d\d|((?i)AM|PM)|(::ffff:)?(({dest_ip}[a-fA-F0-9.:]+)|({dest_host}[\w\-.]+)))\s""",
      """:\d+\.\d+(\+|-)\d+:\d+\s+(::ffff:)?(({dest_ip}[a-fA-F0-9.:]+)|({dest_host}[\w\-.]+))\s"""
    ]
    DupFields = [ "directory->process_directory" ]
  }
```