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
      """exabeam_host=(::ffff:)?([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """(::ffff:)?({host}[^\s\/]{1,2000})\/Microsoft-Windows-Security-Auditing \(4776\)""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]{1,2000}>)\s{0,100}(?!(?:[A-Fa-f:\d.]{1,2000}))[^\t,#<\s.]{1,2000}\.({domain}[^\s.",]{1,2000})""",
      """(?!(?:[A-Fa-f:\d.]{1,2000}))[^\s\/.]{1,2000}\.({domain}[^\s\/.]{1,2000})[^\s\/]{0,2000}\/Microsoft-Windows-Security-Auditing \(4776\)""",
      """"dhn":"(?!(?:[A-Fa-f:\d.]{1,2000}))[^".]{1,2000}\.({domain}[^-".]{1,2000})[^"-]{0,2000}""",
      """<Computer>(?!(?:[A-Fa-f:\d.]{1,2000}))[^<.]{1,2000}\.({domain}[^.<]{1,2000})[^<]{0,2000}</Computer>""",
      """Computer(Name)?\s{0,100}(:|=)\s{0,100}"?(?!(?:[A-Fa-f:\d.]{1,2000}))[^\s."]{1,2000}\.({domain}[^\s".]{1,2000})[^\s"]{0,2000}("|\s)""",
      """({event_code}4776)""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """Logon (?:a|A)ccount(:|=)\s{0,100}(({user_email}[^@\s]{1,2000}?@[^\s]{1,2000}?\.[^\s]{1,2000}?)|(({user}[^@\s,;=]{1,2000}?)(?:@({domain}[^\s.;,@=]{1,2000}).*?)?)|({=user}.+?))[\s;]{0,2000}Source Workstation(:|=)""",
      """Error Code(:|=)\s{0,100}({result_code}[\w\-]{1,2000})""",
      """Source Workstation(:|=)([\s\\]{1,2000}|(\s{0,100}\\*(((::ffff:)?({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}))(:({dest_port}\d{1,100}))?)|(::ffff:)?({dest_host}[^\s]{1,2000}?))[\s;]{0,2000}))Error Code(:|=)"""
    ]
  }
```