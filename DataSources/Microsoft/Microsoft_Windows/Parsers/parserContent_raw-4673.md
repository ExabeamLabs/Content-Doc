#### Parser Content
```Java
{
Name = raw-4673
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-privileged-access"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["A privileged service was called", "Privileges"]
    Fields = [
      """({event_name}A privileged service was called)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?({host}[\w\-.]+)\s"""
      """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))\s"""
      """({host}[\w\-.]+)\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({outcome}(?i)(((audit|success|failure)( |_)(success|audit|failure))|information))\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]+>)\s{0,100}({host}[^=]+?)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]+>)\s{0,100}""",
      """({host}[\w.\-]+)\s{0,100}:\s{1,100}A privileged service was called""",
      """({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4673\)""",
      """"dhn":"({host}[^-"]+)""",
      """Event Type\s{0,100}:\s{0,100}({outcome}.+?)\.\s{1,100}Log Type""",
      """Type\s{0,100}=\s{0,100}"({outcome}[^";]+)"""",
      """Keywords=({outcome}.+?);?\s{0,100}Message=""",
      """<Computer>({host}[^<]+)</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s{0,100}"?({host}.+?)("|\s|;)""",
      """\s{0,100}Source Address(:|=)\s{0,100}(?:-|({src_ip}[^\s]+))\s{0,100}Source Port(:|=)""",
      """({event_code}4673)""",
      """Process Name(:|=)\s{0,100}(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))[\s;]*Service Request Information(:|=)""",
      """\s{0,100}Account Name(:|=)\s{0,100}({user}.+?)[\s;]*Account Domain(:|=)""",
      """\s{0,100}Account Domain(:|=)\s{0,100}({domain}.+?)[\s;]*Logon ID(:|=)""",
      """\s{0,100}Logon ID(:|=)\s{0,100}({logon_id}.+?)[\s;]*Service(:|=)""",
      """\s{0,100}Server(:|=)\s{0,100}({object_server}.+?)[\s;]*Service Name""",
      """\s{0,100}Privileges(:|=)\s{0,100}({privileges}.+?)(\s{0,100}$|\s{1,100}\d{1,100}|\"|,|;)""",
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```