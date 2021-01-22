#### Parser Content
```Java
{
Name = raw-4776-2
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4776"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["attempted to validate the credentials for an account", "Authentication Package", "Microsoft-Windows-Security-Auditing"]
    Fields = [
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """exabeam_host=(::ffff:)?([^=]+?@\s*)?({host}[\w.-]+)""",
      """(::ffff:)?({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4776\)""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s*(\s|\t|,|#\d+|<[^>]+>)\s*(?!(?:[A-Fa-f:\d.]+))[^\t,#<\s.]+\.({domain}[^\s.",]+)""",
      """(?!(?:[A-Fa-f:\d.]+))[^\s\/.]+\.({domain}[^\s\/.]+)[^\s\/]*\/Microsoft-Windows-Security-Auditing \(4776\)""",
      """"dhn":"(?!(?:[A-Fa-f:\d.]+))[^".]+\.({domain}[^-".]+)[^"-]*""",
      """<Computer>(?!(?:[A-Fa-f:\d.]+))[^<.]+\.({domain}[^.<]+)[^<]*</Computer>""",
      """Computer(Name)?\s*(:|=)\s*"?(?!(?:[A-Fa-f:\d.]+))[^\s."]+\.({domain}[^\s".]+)[^\s"]*("|\s)""",
      """({event_code}4776)""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """Logon (?:a|A)ccount(:|=)\s*(({user_email}[^@\s]+?@[^\s]+?\.[^\s]+?)|(({user}[^@\s,;=]+?)(?:@({domain}[^\s.;,@=]+).*?)?)|({=user}.+?))[\s;]*Source Workstation(:|=)""",
      """Error Code(:|=)\s*({result_code}[\w\-]+)""",
      """Source Workstation(:|=)([\s\\]+|(\s*\\*(((::ffff:)?({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+))(:({dest_port}\d+))?)|(::ffff:)?({dest_host}[^\s]+?))[\s;]*))Error Code(:|=)"""
    ]
  }
```