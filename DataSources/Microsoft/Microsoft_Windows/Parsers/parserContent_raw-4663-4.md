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
      """Microsoft-Windows-Security-Auditing.+?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=(::ffff:)?({host}[\w.\-]+)""",
      """(?i)(((audit|success)( |_)(success|audit))|information)[\s,](::ffff:)?({host}[\w\-.]+).*Subject:""",
      """({event_code}4663)""",
      """({time}\w+\s\d+\s\d+:\d+:\d+\s\d+)""",
      """(?i)\w+\s*\d+\s*\d+:\d+:\d+\s+(::ffff:)?(am|pm|({host}[\w\-.]+))""",
      """Subject(:|=).*?Security ID(:|=)\s*({user_sid}.+?)[\s;]*Account Name(:|=)\s*({user}.+?)[\s;]*Account Domain(:|=)\s*(NT AUTHORITY|({domain}.+?))[\s;]*Logon ID(:|=)\s*({logon_id}[^\s;]+)[\s;]*Object(:|=)""",
      """Object(:|=).*?Object Type(:|=)\s*({file_type}.+?)[\s;]*Object Name(:|=)\s*({file_path}({file_parent}.*?)({file_name}[^\\\/;]+?(\.({file_ext}[^\.;\\]+?))?))[\s;]*Handle ID(:|=)""",
      """Process Name(:|=)\s*(?:|({process}.+?))[\s;]*Access Request Information(:|=)""",
      """Process Name(:|=).*\\({process_name}[^\\;]+?)[\s;]*Access Request Information(:|=)""",
      """Process Name(:|=)\s*(?:|({process}({directory}(\w:)?(?:[^:;]+)?[\\\/])?({process_name}[^\\\/";]+?)))[\s;]*Access Request Information(:|=)""",
      """Accesses(:|=)\s*({accesses}.+?)[\s;]*Access Mask(:|=)\s*({access_mask}\w+)""",
      """"AccessList":"({accesses}[^"]+?)\s*"""",
      """"Account":"(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+)""",
      """"SubjectUserSid":"({user_sid}[^\s"]+)""",
      """"SubjectLogonId":"({logon_id}[^\s"]+)""",
      """"ObjectName":"(-|({file_path}({file_parent}.*?)({file_name}[^\\\/;]+?(\.({file_ext}[^\.;]+?))?)))\s*"""",
      """"ObjectType":"(-|({file_type}[^\s"]+))""",
      """"ProcessName":"(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))\s*"""",
      """(?i)\w+\s*\d+\s*\d+:\d+:\d+\s+(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|({dest_host}[\w\-.]+)))"""
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```