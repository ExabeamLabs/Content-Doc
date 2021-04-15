#### Parser Content
```Java
{
Name = raw-4672
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-privileged-access"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["""Special privileges assigned to new logon""", """Privileges"""]
    Fields = [
      """exabeam_host=(::ffff:)?([^=]+?@\s*)?({host}[\w.-]+)""",
      """\d\d:\d\d:\d\d(\+|-)\d\d:\d\d ({host}[^\s]+)""",
      """<\d+>(?i)\w+\s*\d+\s*\d+:\d+:\d+\s+(am\s+|pm\s+)?(::ffff:)?({host}[\w\-.]+)\s"""
      """<\d+>(?i)\w+\s*\d+\s*\d+:\d+:\d+\s+(am\s+|pm\s+)?(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))\s"""
      """"host":"(::ffff:)?({host}[^"]+)""""
      """({event_name}Special privileges assigned to new logon)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """(::ffff:)?({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
      """\scategoryOutcome=(|/({outcome}[^=]+?))(\s+\w+=|\s*$)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({outcome}(?i)(((audit|success|failure)( |_)(success|audit|failure))|information))\s*(\s|\t|,|#\d+|<[^>]+>)\s*({host}[^=]+?)\s*(\s|\t|,|#\d+|<[^>]+>)\s*""",
      """(::ffff:)?({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4672\)""",
      """"dhn":"(::ffff:)?({host}[^-"]+)""",
      """Type\s*=\s*"({outcome}[^";]+)"""",
      """Keywords=({outcome}[^=]+?);?\s*(\w+=)""",
      """<Computer>(::ffff:)?({host}[^<]+)</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s*"?(::ffff:)?({host}[^\s";]+)""",
      """({event_code}4672)""",
      """Account Name(:|=)\s*(-|SYSTEM|({user}[^\s]+?))[\s;]*Account Domain(:|=)""",
      """Account Domain(:|=)\s*(-|({domain}[^\s]+?))[\s;]*Logon ID(:|=)""",
      """\s*Logon ID(:|=)\s*({logon_id}[^=]+?)[\s;]*Privileges(:|=)\s*({privileges}.+?)(<|\s*User:|\s+\d+|,|\s*"|;|\s*$|\s*\(EventID)""",
      """sourceip="({src_ip}[a-fA-F\d:.]+)"""",
      """EVENT_TYPE="({outcome}[^"]+)""""
    ]
    DupFields = ["host->dest_host"]
  }
```