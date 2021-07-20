#### Parser Content
```Java
{
Name = raw-552
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-switch"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["Logon attempt using explicit credentials", "Target Logon GUID:"]
    Fields = [
      """({event_name}Logon attempt using explicit credentials)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success)( |_)(success|audit))|information)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]{1,2000}>)\s{0,100}({host}[^=]{1,2000}?)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]{1,2000}>)\s{0,100}""",
      """({event_code}552)""",
      """({host}[^\s\/]{1,2000})\/Security \(552\)""",
      """<Computer>({host}[^<]{1,2000})</Computer>""",
      """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)""",
      """ComputerName=({host}[\w.\-]{1,2000})""",
      """User Name:\s{0,100}({user}[\w\-\.]{1,2000}(?:\s{0,100}\w+)?\$?)\s{0,100}Domain:""",
      """Domain:\s{0,100}({domain}[\w\-\.]{1,2000}(?:[\s\.\-\w])*?)\s{0,100}Logon ID:""",
      """Logon ID:\s{0,100}\(\w+(\,|\s)({logon_id}\w+)\)\s{0,100}Logon GUID:""",
      """Logon GUID:\s{0,100}(?:-|\{({user_logon_guid}[^}]{1,2000})\})""",
      """Target User Name:\s{0,100}({account}[\w\-\.]{1,2000}(?:\s\w+)?\$?)\s{0,100}Target Domain:""",
      """Target Domain:\s{0,100}({account_domain}[\w\-\.]{1,2000}(?:[\s\.\-\w])*?)\s{0,100}Target Logon GUID:""",
      """Target Logon GUID:\s{0,100}(?:-|\{({account_logon_guid}[^}]{1,2000})\})\s{0,100}Target Server Name:""",
      """Target Server Name:\s{0,100}({dest_host}.+?)\s{0,100}Target Server Info:""",
      """Target Server Info:\s{0,100}({dest_service}.+?)\s{0,100}Caller Process ID:""",
      """Source Network Address:\s{1,100}(?:-|({src_ip}[a-fA-F:\d.]{1,2000}))"""
    ]
  }
```