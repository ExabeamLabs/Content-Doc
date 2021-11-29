#### Parser Content
```Java
{
Name = raw-4672
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-privileged-access"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["""Special privileges assigned to new logon""", """Privileges"""]
    Fields = [
      """exabeam_host=(::ffff:)?([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """\d\d:\d\d:\d\d(\+|-)\d\d:\d\d ({host}[^\s]{1,2000})""",
      """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?({host}[\w\-.]{1,2000})\s"""
      """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]{1,2000}))\s"""
      """"host":"(::ffff:)?({host}[^"]{1,2000})""""
      """({event_name}Special privileges assigned to new logon)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """(::ffff:)?({host}[\w\-.]{1,2000})\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
      """\scategoryOutcome=(|/({outcome}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({outcome}(?i)(((audit|success|failure)( |_)(success|audit|failure))|information))\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]{1,2000}>)\s{0,100}({host}[^=]{1,2000}?)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]{1,2000}>)\s{0,100}""",
      """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)\s({host}[\w\-.]{1,2000})""",
      """(::ffff:)?({host}[^\s\/]{1,2000})\/Microsoft-Windows-Security-Auditing \(4672\)""",
      """"dhn":"(::ffff:)?({host}[^-"]{1,2000})""",
      """Type\s{0,100}=\s{0,100}"({outcome}[^";]{1,2000})"""",
      """Keywords=({outcome}[^=]{1,2000}?);?\s{0,100}(\w+=)""",
      """<Computer>(::ffff:)?({host}[^<]{1,2000})</Computer>""",
      """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?(::ffff:)?({host}[^\s";]{1,2000})""",
      """({event_code}4672)""",
      """Account Name(:|=)\s{0,100}(-|SYSTEM|({user}[^\s]{1,2000}?))[\s;]{0,2000}Account Domain(:|=)""",
      """Account Domain(:|=)\s{0,100}(-|({domain}[^\s]{1,2000}?))[\s;]{0,2000}Logon ID(:|=)""",
      """\s{0,100}Logon ID(:|=)\s{0,100}({logon_id}[^=]{1,2000}?)[\s;]{0,2000}Privileges(:|=)\s{0,100}({privileges}.+?)(<|\s{0,100}User:|\s{1,100}\d{1,100}|,|\s{0,100}"|;|\s{0,100}$|\s{0,100}\(EventID)""",
      """sourceip="({src_ip}[a-fA-F\d:.]{1,2000})"""",
      """EVENT_TYPE="({outcome}[^"]{1,2000})""""
    ]
    DupFields = ["host->dest_host"]
  

}
```