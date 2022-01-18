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
      """EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""", 
      """({event_name}A user account was created)""",
      """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({event_code}4720)""", 
      """exabeam_host=({host}[A-Fa-f:\d.]{1,2000})""",
      """Hostname":"({host}[^"]{1,2000})"""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(,|\s{1,100})({host}[\w.\-]{1,2000}),?""",
      """({host}[^\/\s]{1,2000})\/Microsoft-Windows-Security-Auditing \(4720\)""",
      """"dhn":"({host}[^-"]{1,2000})"""
      """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)""",
      """"system_name":"({host}[^"]{1,2000})"""",
      """Security(,|\srn=|\s{1,100})({record_id}\d{1,100})""",
      """Account Name:\s{1,100}({user}[^:]{1,2000}?)\s{1,100}Account Domain:\s{1,100}({domain}[^\s]{1,2000}).+?Logon ID:\s{1,100}({logon_id}[^\s]{1,2000}).+?Account Name:\s{1,100}({account_name}[^:]{1,2000}?)\s{1,100}Account Domain:\s{1,100}({account_domain}[^\s]{1,2000})\s{1,100}Attributes""",
      """Subject:\s{1,100}Security ID:\s{1,100}({user_sid}[^\s]{1,2000}).+?Account Name:\s{1,100}({user}[^:]{1,2000}?)\s{1,100}Account Domain:\s{1,100}({domain}[^\s]{1,2000}).+?Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
      """New Account:.+?Security ID:\s{1,100}({account_id}[^\s]{1,2000})\s{1,100}Account Name:\s{1,100}({account_name}[\w.'\-]{1,2000})\s{1,100}Account Domain:\s{1,100}({account_domain}[^\s]{1,2000})""",
      """Enabled.*?'({user_type}[^']{1,2000})"""
 ]
 DupFields = ["host->dest_host"]


}
```