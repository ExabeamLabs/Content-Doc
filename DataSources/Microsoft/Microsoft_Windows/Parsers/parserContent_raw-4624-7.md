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
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """Computer(Name)?=({host}[^\s]{1,2000})""",
      """({event_code}4624)""",
      """Logon Type(:|=)\s{0,100}({logon_type}[\d]{1,2000})""",
      """New Logon[^"]{0,2000}?Account Name(:|=)\s{0,100}(-|SYSTEM|({user}[^\s]{1,2000}))""",
      """New Logon[^"]{0,2000}?Account Domain(:|=)\s{0,100}(-|NT AUTHORITY|({domain}[^\s]{1,2000}))""",
      """Process Name(:|=)\s{0,100}(?:-|({process}({directory}[^=]{0,2000}?)(\\+({process_name}[^\\]{1,2000}?))?))\s{1,100}Network Information:""",
      """Workstation Name(:|=)\s{0,100}(-|[A-Fa-f:\d.]{1,2000}|(::ffff:)?({src_host_windows}[^\s;]{1,2000}))[\s;]{0,2000}Source Network Address(:|=)""",
      """Source Network Address(:|=)\s{0,100}(?:-|(::ffff:)?({src_ip}[a-fA-F\d.:]{1,2000}))[\s;]{0,2000}Source Port(:|=)""",
      """Logon Process(:|=)\s{0,100}({auth_process}[^\s;]{1,2000})[\s;]{0,2000}Authentication Package(:|=)\s{0,100}({auth_package}[^\s;]{1,2000})""",
      """Logon ID(:|=)\s{0,100}({logon_id}[^\s;]{1,2000})""", 
      """New Logon(:|=)[\s;]{0,2000}Security ID(:|=)\s{0,100}(NT AUTHORITY\\SYSTEM|({user_sid}[^;:=]{1,2000}?))[\s;]{0,2000}Account Name(:|=)""",
      """:\d{1,100}:\d{1,100}\s{1,100}(\d\d\d\d|((?i)AM|PM)|(::ffff:)?(({dest_ip}[a-fA-F0-9.:]{1,2000})|({dest_host}[\w\-.]{1,2000})))\s""",
      """:\d{1,100}\.\d{1,100}(\+|-)\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}[a-fA-F0-9.:]{1,2000})|({dest_host}[\w\-.]{1,2000}))\s"""
    ]
    DupFields = [ "directory->process_directory" ]
  }
```