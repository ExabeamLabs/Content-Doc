#### Parser Content
```Java
{
Name = raw-4776
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4776"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["attempted to validate the credentials for an account", "Authentication Package"]
    Fields = [
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s*(\s|\t|,|#\d+|<[^>]+>)\s*({host}[^=]+?)\s*(\s|\t|,|#\d+|<[^>]+>)\s*""",
      """({host}[\w.\-]+)\s*:\s+The computer attempted to validate the credentials for an account""",
      """({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4776\)""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s*(\s|\t|,|#\d+|<[^>]+>)\s*(?!(?:[A-Fa-f:\d.]+))[^\t,#<\s.]+\.({domain}[^\s.",]+)""",
      """(?!(?:[A-Fa-f:\d.]+))[^\s\/.]+\.({domain}[^\s\/.]+)[^\s\/]*\/Microsoft-Windows-Security-Auditing \(4776\)""",
      """({event_code}4776)""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """Logon (?:a|A)ccount(:|=)\s*(({user_email}[^@\s]+?@[^\s]+?\.[^\s]+?)|(({user}[^@\s,;=]+?)(?:@({domain}[^\s.;,@=]+).*?)?))[\s;]*Source Workstation(:|=)([\s\\]+|(\s*\\*((({dest_ip}[A-Fa-f:\d.]+?)(:({dest_port}\d+))?)|({dest_host}.+?))[\s;]*))Error Code(:|=)""",
      """Error Code(:|=)\s*({result_code}[\w\-]+)""",
      """Source Workstation(:|=)([\s\\]+|(\s*\\*((({dest_ip}[A-Fa-f:\d.]+?)(:({dest_port}\d+))?)|({dest_host}.+?))[\s;]*))Error Code(:|=)""",
    ]
  }
```