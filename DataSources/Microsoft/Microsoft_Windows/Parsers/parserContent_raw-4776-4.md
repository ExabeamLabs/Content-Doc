#### Parser Content
```Java
{
Name = raw-4776-4
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4776"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["attempted to validate the credentials for an account", "Authentication Package",
    "computer_name"]
    Fields = [
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]+>)\s{0,100}(?!(?:[A-Fa-f:\d.]+))[^\t,#<\s.]+\.({domain}[^\s.",]+)""",
      """"(?:winlog\.)?computer_name\\*":\\*"({host}[^\\"]+)""",
      """@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """({event_code}4776)""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """Logon (?:a|A)ccount(:|=)\s{0,100}(({user_email}[^@\s]+?@[^\s]+?\.[^\s]+?)|(({user}[^@\s,;=]+?)(?:@({domain}[^\s.;,@=]+).*?)?))[\s;]*Source Workstation(:|=)([\s\\]+|(\s{0,100}\\*((({dest_ip}[A-Fa-f:\d.]+?)(:({dest_port}\d{1,100}))?)|({dest_host}.+?))[\s;]*))Error Code(:|=)""",
      """Error Code(:|=)\s{0,100}({result_code}[\w\-]+)""",
      """Source Workstation(:|=)([\s\\]+|(\s{0,100}\\*((({dest_ip}[A-Fa-f:\d.]+?)(:({dest_port}\d{1,100}))?)|({dest_host}.+?))[\s;]*))Error Code(:|=)""",
    ]
  }
```