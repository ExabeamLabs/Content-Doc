#### Parser Content
```Java
{
Name = raw-windows-account-629
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-account-disabled"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ """User Account Disabled""", """629""" ]
    Fields = [
      """({event_name}User Account Disabled)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})\s{1,100}({event_code}629)\s{1,100}Security\s.+?(?i)((audit|success)( |_)(success|audit))\s{1,100}({host}[^\s]{1,2000})""",
      """({host}[^\/\s]{1,2000})\/Security""",
      """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)""",
      """({event_code}629)""",
      """Target Account Name:\s{1,100}({target_user}.+?)\s{1,100}Target Domain:\s{1,100}({target_domain}.+?)\s{1,100}Target Account ID:.*?({target_user_sid}[\w\-\d]{1,2000})\}?\s{1,100}Caller User Name""",
      """Caller User Name:\s{1,100}(?=\w)({user}.+?)\s{1,100}Caller Domain:\s{1,100}(?=\w)({domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\([^,]{1,2000}
```