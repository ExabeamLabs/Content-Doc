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
      """<\d+>(?i)\w+\s*\d+\s*\d+:\d+:\d+\s+(am\s+|pm\s+)?(::ffff:)?({host}[\w\-.]+)\s"""
      """<\d+>(?i)\w+\s*\d+\s*\d+:\d+:\d+\s+(am\s+|pm\s+)?(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))\s"""
      """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({outcome}(?i)(((audit|success|failure)( |_)(success|audit|failure))|information))\s*(\s|\t|,|#\d+|<[^>]+>)\s*({host}[^=]+?)\s*(\s|\t|,|#\d+|<[^>]+>)\s*""",
      """({host}[\w.\-]+)\s*:\s+A privileged service was called""",
      """({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4673\)""",
      """"dhn":"({host}[^-"]+)""",
      """Event Type\s*:\s*({outcome}.+?)\.\s+Log Type""",
      """Type\s*=\s*"({outcome}[^";]+)"""",
      """Keywords=({outcome}.+?);?\s*Message=""",
      """<Computer>({host}[^<]+)</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s|;)""",
      """\s*Source Address(:|=)\s*(?:-|({src_ip}[^\s]+))\s*Source Port(:|=)""",
      """({event_code}4673)""",
      """Process Name(:|=)\s*(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))[\s;]*Service Request Information(:|=)""",
      """\s*Account Name(:|=)\s*({user}.+?)[\s;]*Account Domain(:|=)""",
      """\s*Account Domain(:|=)\s*({domain}.+?)[\s;]*Logon ID(:|=)""",
      """\s*Logon ID(:|=)\s*({logon_id}.+?)[\s;]*Service(:|=)""",
      """\s*Server(:|=)\s*({object_server}.+?)[\s;]*Service Name""",
      """\s*Privileges(:|=)\s*({privileges}.+?)(\s*$|\s+\d+|\"|,|;)""",
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```