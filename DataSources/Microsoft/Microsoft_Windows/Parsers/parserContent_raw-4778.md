#### Parser Content
```Java
{
Name = raw-4778
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4778"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["A session was reconnected to a Window Station", "Session Name"]
    Fields = [
      """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
      """({event_name}A session was reconnected to a Window Station)""",
      """({host}[\w\-.]+)\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success)( |_)(success|audit))|information)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]+>)\s{0,100}({host}[^=]+?)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]+>)\s{0,100}""",
      """({host}[\w.\-]+)\s{0,100}:\s{1,100}A session was reconnected to a Window Station""",
      """({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4778\)""",
      """"dhn":"({host}[^-"]+)""",
      """<Computer>({host}[^<]+)</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s{0,100}"?({host}.+?)("|\s|;)""",
      """({event_code}4778)""",
      """Account Name(:|=)\s{0,100}({user}[^\s;]+)[\s;]*Account Domain(:|=)""",
      """Account Domain(:|=)\s{0,100}({domain}[^\s;]+)[\s;]*Logon ID(:|=)""",
      """Service Name(:|=)\s{0,100}({dest_host}.+?)[\s;]*Service ID""",
      """Client Address(:|=)\s{0,100}(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)"""
    ]
  }
```