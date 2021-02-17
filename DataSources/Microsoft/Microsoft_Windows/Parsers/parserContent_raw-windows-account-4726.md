#### Parser Content
```Java
{
Name = raw-windows-account-4726
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-account-deleted"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "A user account was deleted" ]
    Fields = [
      """({event_name}A user account was deleted)""",
      """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """Security\s+({record_id}[\d]+)""",
      """Security,({record_id}[\d]+),(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)""",
      """({event_code}4726)""",
      """exabeam_host=({host}[\w.\-]+)""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(\s+|,)({host}[^\s,]+)""",
      """({host}[^\/\s]+)\/Microsoft-Windows-Security-Auditing \(4726\)""",
      """"dhn":"({host}[^-"]+)""",
      """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
      """"system_name":"({host}[^"]+)"""",
      """Subject:\s+Security ID:\s+({user_sid}.+?)\s+Account Name:\s+(?=\w)({user}.+?)\s+Account Domain:\s+(?=\w)({domain}.+?)\s+Logon ID""",
      """Logon ID:\s+({logon_id}[^\s]+)""",
      """Target Account.+?Security ID:\s+(%\{)?({target_user_sid}[\w\d\-]+?)\}?\s+Account Name:"""
      """Target Account.+?Account Name:\s+({target_user}.+?)\s+Account Domain:\s+({target_domain}.+?)\s+Additional"""
    ]
    DupFields=[ "host->dest_host", "target_user->account_name" ]
  }
```