#### Parser Content
```Java
{
Name = raw-4776-3
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4776"
    TimeFormat = "MM/dd/yyyy HH:mm:ss a"
    Conditions = ["attempted to validate the credentials for an account", "Authentication Package",
    "Computer"]
    Fields = [
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(AM|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """Computer(Name)?\s{0,100}(:|=)\s{0,100}"?(?!(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))[^\s.";]+\.({domain}[^\s";]+)[^\s"]*("|\s|;)""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]+>)\s{0,100}(?!(?:[A-Fa-f:\d.]+))[^\t,#<\s.]+\.({domain}[^\s.",]+)""",
      """"dhn":"(?!(?:[A-Fa-f:\d.]+))[^".]+\.({domain}[^-".]+)[^"-]*""",
      """<Computer>({host}[^<]+)</Computer>""",
      """<Computer>(?!(?:[A-Fa-f:\d.]+))[^<.]+\.({domain}[^.<]+)[^<]*</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s{0,100}"?({host}[^:=]+?)("|\s|;)""",
      """Computer(Name)?\s{0,100}(:|=)\s{0,100}"?(?!(?:[A-Fa-f:\d.]+))[^\s."]+\.({domain}[^\s".]+)[^\s"]*("|\s)""",
      """({event_code}4776)""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """Logon (?:a|A)ccount(:|=)\s{0,100}(({user_email}[^@\s]+?@[^\s]+?\.[^\s]+?)|(({user}[^@\s,;=]+?)(?:@({domain}[^\s.;,@=]+).*?)?))[\s;]*Source Workstation(:|=)""",
      """Error Code(:|=)\s{0,100}({result_code}[\w\-]+)""",
      """Source Workstation(:|=)([\s\\]+|(\s{0,100}\\*((({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d{1,100}))?)|({dest_host}[\w\-]+)[^:=]*?)[\s;]*))Error Code(:|=)"""
    ]
  }
```