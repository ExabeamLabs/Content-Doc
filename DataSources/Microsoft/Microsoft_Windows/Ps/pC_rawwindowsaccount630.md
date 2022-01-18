#### Parser Content
```Java
{
Name = raw-windows-account-630
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-account-deleted"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "User Account Deleted", "Caller User Name:", "Logon ID:", "Target Account Name:" ]
    Fields = [
      """({event_name}User Account Deleted)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """Security,({record_id}[\d]{1,2000}),(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})""",
      """({event_code}630)""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(\s{1,100}|,)({host}[\w.\-]{1,2000})""",
      """({host}[^\/\s]{1,2000})\/Security \(630\)""",
      """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)""",
      """Target Account Name:\s{1,100}(?=\w)({target_user}.+?)\s{1,100}Target Domain:\s{1,100}(?=\w)({target_domain}.+?)\s{1,100}Target Account ID:\s\%\{({target_user_sid}[^}]{1,2000})\}""",
      """Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller Domain:\s{1,100}({domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\([^,]{1,2000

}
```