#### Parser Content
```Java
{
Name = raw-windows-account-630
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-account-deleted"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "User Account Deleted" ]
    Fields = [
      """({event_name}User Account Deleted)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """Security,({record_id}[\d]+),(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})""",
      """({event_code}630)""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(\s{1,100}|,)({host}[\w.\-]+)""",
      """({host}[^\/\s]+)\/Security \(630\)""",
      """Computer(\w+)?["\s]*(:|=)\s{0,100}"?({host}.+?)("|\s)""",
      """Target Account Name:\s{1,100}(?=\w)({target_user}.+?)\s{1,100}Target Domain:\s{1,100}(?=\w)({target_domain}.+?)\s{1,100}Target Account ID:\s\%\{({target_user_sid}[^}]+)\}""",
      """Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller Domain:\s{1,100}({domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\([^,]+,({logon_id}[^\)]+)"""
    ]
    DupFields=[ "host->dest_host", "target_user->account_name" ]
  }
```