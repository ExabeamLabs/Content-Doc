#### Parser Content
```Java
{
Name = raw-4663-4
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4663"
    IsHVF = true
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["An attempt was made to access an object.", "Microsoft-Windows-Security-Auditing"]
    Fields = [
      """({event_name}An attempt was made to access an object)""",
      """Microsoft-Windows-Security-Auditing[^":=]+?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=(::ffff:)?({host}[\w.\-]+)""",
      """(?i)(((audit|success)( |_)(success|audit))|information)[\s,](::ffff:)?({host}[\w\-.]+).*Subject:""",
      """({event_code}4663)""",
      """({time}\w+\s\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}\s\d{1,100})""",
      """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(am|pm|({host}[\w\-.]+))""",
      """Subject(:|=)[^:=]*?Security ID(:|=)\s{0,100}((NT AUTHORITY|([^\\=]+?))\\+)?(SYSTEM|({user_sid}[^=\s]+?))[\s;]*Account Name(:|=)\s{0,100}({user}[^\s;]+?)[\s;]*Account Domain(:|=)\s{0,100}(NT AUTHORITY|({domain}[^:=]+?))[\s;]*Logon ID(:|=)\s{0,100}({logon_id}[^\s;]+)[\s;]*Object(:|=)""",
      """Object Type(:|=)\s{0,100}({file_type}[^:=]+?)[\s;]*Object Name(:|=)\s{0,100}({file_path}({file_parent}(\w:)?[^:=]+[\\\/]+)?({file_name}[^:=\\\/]+?(\.({file_ext}\w+))?))[\s;]*Handle ID(:|=)""",
      """Process Name(:|=)\s{0,100}(?:|({process}({directory}(\w:)?(?:[^:;]+)?[\\\/])?({process_name}[^\\\/";]+?)))[\s;]*Access Request Information(:|=)""",
      """Accesses(:|=)\s{0,100}({accesses}[^:]+?)[\s;]*Access Mask(:|=)\s{0,100}({access_mask}\w+)""",
      """"AccessList":"({accesses}[^"]+?)\s{0,100}"""",
      """"Account":"(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+)""",
      """"SubjectUserSid":"({user_sid}[^\s"]+)""",
      """"SubjectLogonId":"({logon_id}[^\s"]+)""",
      """"ObjectName":"(-|({file_path}({file_parent}[^"]+?)({file_name}[^\\\/;]+?(\.({file_ext}[^\.;]+?))?)))\s{0,100}"""",
      """"ObjectType":"(-|({file_type}[^\s"]+))""",
      """"ProcessName":"(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))\s{0,100}"""",
      """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|({dest_host}[\w\-.]+)))"""
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```