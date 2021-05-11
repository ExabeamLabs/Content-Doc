#### Parser Content
```Java
{
Name = raw-4776-1
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4776"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["attempted to validate the credentials for an account", "Authentication Package", "dhn"]
    Fields = [
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]+>)\s{0,100}(?!(?:[A-Fa-f:\d.]+))[^\t,#<\s.]+\.({domain}[^\s.",]+)""",
      """(?!(?:[A-Fa-f:\d.]+))[^\s\/.]+\.({domain}[^\s\/.]+)[^\s\/]*\/Microsoft-Windows-Security-Auditing \(4776\)""",
      """"dhn":"({host}[^-"]+)""",
      """"dhn":"(?!(?:[A-Fa-f:\d.]+))[^".]+\.({domain}[^-".]+)[^"-]*""",
      """<Computer>(?!(?:[A-Fa-f:\d.]+))[^<.]+\.({domain}[^.<]+)[^<]*</Computer>""",
      """Computer(Name)?\s{0,100}(:|=)\s{0,100}"?(?!(?:[A-Fa-f:\d.]+))[^\s."]+\.({domain}[^\s".]+)[^\s"]*("|\s)""",
      """({event_code}4776)""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """Logon (?:a|A)ccount(:|=)\s{0,100}(({user_email}[^@\s]+?@[^\s]+?\.[^\s]+?)|(({user}[^@\s,;=]+?)(?:@({domain}[^\s.;,@=]+).*?)?))[\s;]*Source Workstation(:|=)([\s\\]+|(\s{0,100}\\*((({dest_ip}[A-Fa-f:\d.]+?)(:({dest_port}\d{1,100}))?)|({dest_host}.+?))[\s;]*))Error Code(:|=)""",
      """Error Code(:|=)\s{0,100}({result_code}[\w\-]+)""",
      """Source Workstation(:|=)([\s\\]+|(\s{0,100}\\*((({dest_ip}[A-Fa-f:\d.]+?)(:({dest_port}\d{1,100}))?)|({dest_host}.+?))[\s;]*))Error Code(:|=)""",
    ]
  }
```