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
      """({event_name}A session was reconnected to a Window Station)""",
      """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success)( |_)(success|audit))|information)\s*(\s|\t|,|#\d+|<[^>]+>)\s*({host}[^=]+?)\s*(\s|\t|,|#\d+|<[^>]+>)\s*""",
      """({host}[\w.\-]+)\s*:\s+A session was reconnected to a Window Station""",
      """({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4778\)""",
      """"dhn":"({host}[^-"]+)""",
      """<Computer>({host}[^<]+)</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s|;)""",
      """({event_code}4778)""",
      """Account Name(:|=)\s*({user}[^\s;]+)[\s;]*Account Domain(:|=)""",
      """Account Domain(:|=)\s*({domain}[^\s;]+)[\s;]*Logon ID(:|=)""",
      """Service Name(:|=)\s*({dest_host}.+?)[\s;]*Service ID""",
      """Client Address(:|=)\s*(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)"""
    ]
  }
```