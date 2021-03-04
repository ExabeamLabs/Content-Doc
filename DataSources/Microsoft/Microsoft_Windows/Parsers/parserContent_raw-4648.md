#### Parser Content
```Java
{
Name = raw-4648
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-account-switch"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["A logon was attempted using explicit credentials", "Target Server Name"]
    Fields = [
      """({event_name}A logon was attempted using explicit credentials)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success)( |_)(success|audit))|information)\s*(\s|\t|,|#\d+|<[^>]+>)\s*({host}[^=]+?)\s*(\s|\t|,|#\d+|<[^>]+>)\s*""",
      """({host}[\w.\-]+)\s*:\s+A logon was attempted using explicit credentials""",
      """({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4648\)""",
      """"dhn":"({host}[^-"]+)""",
      """<Computer>({host}[^<]+)</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s|;)""",
      """({event_code}4648)""",
      """Subject(:|=)[\s;]*Security ID(:|=)\s*({user_sid}.*?)[\s;]*Account Name(:|=)""",
      """Subject(:|=).+?Account Name(:|=)\s*(?:-|({user}.*?))[\s;]*Account Domain(:|=)""",
      """Subject(:|=).+?Account Domain(:|=)\s*(?:-|NT Service|({domain}.*?))[\s;]*Logon ID(:|=)""",
      """Subject(:|=).+?Logon ID(:|=)\s*({logon_id}.*?)[\s;]*Logon GUID(:|=)""",
      """Subject(:|=).+?Logon GUID(:|=)\s*\{({user_logon_guid}[^}]+)\}[\s;]*Account Whose""",
      """Used(:|=);?\s*Account Name(:|=)\s*({account}.*?)[\s;]*Account Domain(:|=)"""
      """Used(:|=).+?Account Domain(:|=)\s*(|({account_domain}.*?))[\s;]*Logon GUID(:|=)""",
      """Used(:|=).+?Logon GUID(:|=)\s*\{({account_logon_guid}.*?)\}[\s;]*Target Server(:|=)""",
      """Target Server Name(:|=)\s*({dest_host}.*?)[\s;]*Additional Information(:|=)""",
      """Additional Information(:|=)\s*({dest_service}.*?)[\s;]*Process Information(:|=)""",
      """Process ID(:|=)\s*({process_id}.*?)[\s;]*Process Name(:|=)""",
      """Process Name(:|=)\s*(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))[\s;]*Network Information(:|=)""",
      """Network Address(:|=)\s*(?:-|({src_ip}[a-fA-F:\d.]+))"""
    ]
    DupFields = ["directory->process_directory"]
  }
```