#### Parser Content
```Java
{
Name = raw-windows-account-4720
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-created"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "A user account was created" ]
  Fields = [ 
      """({event_name}A user account was created)""",
      """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({event_code}4720)""", 
      """exabeam_host=({host}[A-Fa-f:\d.]+)""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(,|\s{1,100})({host}[\w.\-]+),?""",
      """({host}[^\/\s]+)\/Microsoft-Windows-Security-Auditing \(4720\)""",
      """"dhn":"({host}[^-"]+)"""
      """Computer(\w+)?["\s]*(:|=)\s{0,100}"?({host}.+?)("|\s)""",
      """"system_name":"({host}[^"]+)"""",
      """Security(,|\srn=|\s{1,100})({record_id}\d{1,100})""",
      """Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain:\s{1,100}({domain}[^\s]+).+?Logon ID:\s{1,100}({logon_id}[^\s]+).+?Account Name:\s{1,100}({account_name}.+?)\s{1,100}Account Domain:\s{1,100}({account_domain}[^\s]+)\s{1,100}Attributes""",
      """Subject:\s{1,100}Security ID:\s{1,100}({user_sid}[^\s]+).+?Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain:\s{1,100}({domain}[^\s]+).+?Logon ID:\s{1,100}({logon_id}[^\s]+)""",
      """New Account:.+?Security ID:\s{1,100}({account_id}[^\s]+)\s{1,100}Account Name:\s{1,100}({account_name}[\w.'\-]+)\s{1,100}Account Domain:\s{1,100}({account_domain}[^\s]+)""",
      """Enabled.*?'({user_type}[^']+)"""
 ]
 DupFields = ["host->dest_host"]
}
```