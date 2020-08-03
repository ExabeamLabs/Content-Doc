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
      """(?i)(((audit|success)( |_)(success|audit))|information)\s*(\s|\t|,|#\d+|<[^>]+>)\s*({host}[^=]+?)\s*(\s|\t|,|#\d+|<[^>]+>)\s*""",
      """({event_code}552)""",
      """({host}[^\s\/]+)\/Security \(552\)""",
      """<Computer>({host}[^<]+)</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
      """ComputerName=({host}[\w.\-]+)""",
      """User Name:\s*({user}[\w\-\.]+(?:\s*\w+)?\$?)\s*Domain:""",
      """Domain:\s*({domain}[\w\-\.]+(?:[\s\.\-\w])*?)\s*Logon ID:""",
      """Logon ID:\s*\(\w+(\,|\s)({logon_id}\w+)\)\s*Logon GUID:""",
      """Logon GUID:\s*(?:-|\{({user_logon_guid}[^}]+)\})""",
      """Target User Name:\s*({account}[\w\-\.]+(?:\s\w+)?\$?)\s*Target Domain:""",
      """Target Domain:\s*({account_domain}[\w\-\.]+(?:[\s\.\-\w])*?)\s*Target Logon GUID:""",
      """Target Logon GUID:\s*(?:-|\{({account_logon_guid}[^}]+)\})\s*Target Server Name:""",
      """Target Server Name:\s*({dest_host}.+?)\s*Target Server Info:""",
      """Target Server Info:\s*({dest_service}.+?)\s*Caller Process ID:""",
      """Source Network Address:\s+(?:-|({src_ip}[a-fA-F:\d.]+))"""
    ]
  }
```