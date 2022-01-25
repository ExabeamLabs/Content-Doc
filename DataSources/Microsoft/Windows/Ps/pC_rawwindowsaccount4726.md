#### Parser Content
```Java
{
Name = raw-windows-account-4726
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-account-deleted"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "A user account was deleted", "Security ID:", "Account Name:" ]
    Fields = [
      """EventTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
      """({event_name}A user account was deleted)""",
      """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """Security\s{1,100}({record_id}[\d]{1,2000})""",
      """Security,({record_id}[\d]{1,2000}),(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})""",
      """({event_code}4726)""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(\s{1,100}|,)({host}[^\s,]{1,2000})""",
      """({host}[^\/\s]{1,2000})\/Microsoft-Windows-Security-Auditing \(4726\)""",
      """"dhn":"({host}[^-"]{1,2000})""",
      """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)""",
      """"system_name":"({host}[^"]{1,2000})"""",
      """Subject:\s{1,100}Security ID:\s{1,100}({user_sid}.+?)\s{1,100}Account Name:\s{1,100}(?=\w)({user}.+?)\s{1,100}Account Domain:\s{1,100}(?=\w)({domain}.+?)\s{1,100}Logon ID""",
      """Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
      """Target Account.+?Security ID:\s{1,100}(%\{)?({target_user_sid}[\w\d\-]{1,2000}?)\}?\s{1,100}Account Name:"""
      """Target Account.+?Account Name:\s{1,100}({target_user}.+?)\s{1,100}Account Domain:\s{1,100}({target_domain}.+?)\s{1,100}Additional"""
    ]
    DupFields=[ "host->dest_host", "target_user->account_name" ]
  

}
```