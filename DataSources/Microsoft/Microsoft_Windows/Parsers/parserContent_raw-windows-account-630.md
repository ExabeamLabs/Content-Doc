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
      """Security,({record_id}[\d]+),(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)""",
      """({event_code}630)""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(\s+|,)({host}[\w.\-]+)""",
      """({host}[^\/\s]+)\/Security \(630\)""",
      """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
      """Target Account Name:\s+(?=\w)({target_user}.+?)\s+Target Domain:\s+(?=\w)({target_domain}.+?)\s+Target Account ID:\s\%\{({target_user_sid}[^}]+)\}""",
      """Caller User Name:\s+({user}.+?)\s+Caller Domain:\s+({domain}.+?)\s+Caller Logon ID:\s+\([^,]+,({logon_id}[^\)]+)"""
    ]
    DupFields=[ "host->dest_host", "target_user->account_name" ]
  }
```