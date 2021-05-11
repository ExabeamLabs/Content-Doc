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
      """exabeam_host=(::ffff:)?([^=]+?@\s{0,100})?({host}[\w.-]+)""",
      """\d\d:\d\d:\d\d(\+|-)\d\d:\d\d ({host}[^\s]+)""",
      """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?({host}[\w\-.]+)\s"""
      """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))\s"""
      """"host":"(::ffff:)?({host}[^"]+)""""
      """({event_name}Special privileges assigned to new logon)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """(::ffff:)?({host}[\w\-.]+)\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
      """\scategoryOutcome=(|/({outcome}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({outcome}(?i)(((audit|success|failure)( |_)(success|audit|failure))|information))\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]+>)\s{0,100}({host}[^=]+?)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]+>)\s{0,100}""",
      """(::ffff:)?({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4672\)""",
      """"dhn":"(::ffff:)?({host}[^-"]+)""",
      """Type\s{0,100}=\s{0,100}"({outcome}[^";]+)"""",
      """Keywords=({outcome}[^=]+?);?\s{0,100}(\w+=)""",
      """<Computer>(::ffff:)?({host}[^<]+)</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s{0,100}"?(::ffff:)?({host}[^\s";]+)""",
      """({event_code}4672)""",
      """Account Name(:|=)\s{0,100}(-|SYSTEM|({user}[^\s]+?))[\s;]*Account Domain(:|=)""",
      """Account Domain(:|=)\s{0,100}(-|({domain}[^\s]+?))[\s;]*Logon ID(:|=)""",
      """\s{0,100}Logon ID(:|=)\s{0,100}({logon_id}[^=]+?)[\s;]*Privileges(:|=)\s{0,100}({privileges}.+?)(<|\s{0,100}User:|\s{1,100}\d{1,100}|,|\s{0,100}"|;|\s{0,100}$|\s{0,100}\(EventID)""",
      """sourceip="({src_ip}[a-fA-F\d:.]+)"""",
      """EVENT_TYPE="({outcome}[^"]+)""""
    ]
    DupFields = ["host->dest_host"]
  }
```