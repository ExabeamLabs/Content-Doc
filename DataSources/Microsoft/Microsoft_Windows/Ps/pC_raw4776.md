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
      """({host}[\w\-.]{1,2000})\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]{1,2000}>)\s{0,100}({host}[^=]{1,2000}?)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]{1,2000}>)\s{0,100}""",
      """({host}[\w.\-]{1,2000})\s{0,100}:\s{1,100}The computer attempted to validate the credentials for an account""",
      """({host}[^\s\/]{1,2000})\/Microsoft-Windows-Security-Auditing \(4776\)""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]{1,2000}>)\s{0,100}(?!(?:[A-Fa-f:\d.]{1,2000}))[^\t,#<\s.]{1,2000}\.({domain}[^\s.",]{1,2000})""",
      """(?!(?:[A-Fa-f:\d.]{1,2000}))[^\s\/.]{1,2000}\.({domain}[^\s\/.]{1,2000})[^\s\/]{0,2000}\/Microsoft-Windows-Security-Auditing \(4776\)""",
      """({event_code}4776)""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """Logon (?:a|A)ccount(:|=)\s{0,100}(({user_email}[^@\s]{1,2000}?@[^\s]{1,2000}?\.[^\s]{1,2000}?)|(({user}[^@\s,;=]{1,2000}?)(?:@({domain}[^\s.;,@=]{1,2000}).*?)?))[\s;]{0,2000}Source Workstation(:|=)([\s\\]{1,2000}|(\s{0,100}\\*((({dest_ip}[A-Fa-f:\d.]{1,2000}?)(:({dest_port}\d{1,100}))?)|({dest_host}.+?))[\s;]{0,2000}))Error Code(:|=)""",
      """Error Code(:|=)\s{0,100}({result_code}[\w\-]{1,2000})""",
      """Source Workstation(:|=)([\s\\]{1,2000}|(\s{0,100}\\*((({dest_ip}[A-Fa-f:\d.]{1,2000}?)(:({dest_port}\d{1,100}))?)|({dest_host}.+?))[\s;]{0,2000}))Error Code(:|=)""",
    ]
  }
```