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
      """exabeam_host=({host}[\w.\-]+)""",
      """(?i)(information)(\s+|,)({host}[\w.\-]+)""",
      """(?i)(success|failure|audit)\s+\w+(\s+|,)({host}[^\s,]+)""",
      """"dhn":"({host}[^-"]+)""",
      """rn=({record_id}[\d]+)""",
      """({host}[^\/\s]+)\/Security \(644\)""",
      """Target Account Name:\s+(?=\w)({user}.+?)\s+Target Account ID:\s+(%\{)?({user_sid}([\w\d\-]+?)|([^\s]+))\}?\s+Caller Machine""",
      """Caller Machine Name:\s+({src_host}.+?)\s+Caller User""",
      """Caller User Name:\s+({caller_user}.+?)\s+Caller Domain:\s+(?=\w)({caller_domain}.+?)\s+Caller Logon ID:\s+\([^,]+,({logon_id}[^\)]+)"""
    ]
    DupFields=["host->dest_host",
      "caller_domain->domain"]
  }
```