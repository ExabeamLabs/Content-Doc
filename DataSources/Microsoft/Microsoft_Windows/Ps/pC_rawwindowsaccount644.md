#### Parser Content
```Java
{
Name = raw-windows-account-644
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-account-lockout"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ """User Account Locked Out""", """644""" ]
    Fields = [    
      """({event_name}User Account Locked Out)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({event_code}644)""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """(?i)(information)(\s{1,100}|,)({host}[\w.\-]{1,2000})""",
      """(?i)(success|failure|audit)\s{1,100}\w+(\s{1,100}|,)({host}[^\s,]{1,2000})""",
      """"dhn":"({host}[^-"]{1,2000})""",
      """rn=({record_id}[\d]{1,2000})""",
      """({host}[^\/\s]{1,2000})\/Security \(644\)""",
      """Target Account Name:\s{1,100}(?=\w)({user}.+?)\s{1,100}Target Account ID:\s{1,100}(%\{)?({user_sid}([\w\d\-]{1,2000}?)|([^\s]{1,2000}))\}?\s{1,100}Caller Machine""",
      """Caller Machine Name:\s{1,100}({src_host}.+?)\s{1,100}Caller User""",
      """Caller User Name:\s{1,100}({caller_user}.+?)\s{1,100}Caller Domain:\s{1,100}(?=\w)({caller_domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\([^,]{1,2000

}
```