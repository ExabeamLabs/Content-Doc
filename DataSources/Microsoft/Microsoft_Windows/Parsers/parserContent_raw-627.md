#### Parser Content
```Java
{
Name = raw-627
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-password-change"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "Change Password Attempt:"]
    Fields = [ 
      """({event_name}Change Password Attempt)""",
      """({time}\w+ \d{1,2} [\d:]+ \d{1,100})""",
      """Security,({record_id}\d{1,100})""",
      """\sType=({outcome}.+?)\s{1,100}\w+=""",
      """exabeam_host=({host}[\w.\-]+)""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(,|\s)({host}[\w\-.]+)""",
      """({host}[\w\-.]+)\/Security""",
      """Computer=({host}[\w\-.]+)""",
      """\s{1,100}({outcome}(?i)((audit|success|failure)( |_)(success|audit|failure)))\s{1,100}""",
      """({event_code}627)""",
      """Target Account Name\s{0,100}:\s{0,100}(?=\w)({target_user}.+?)\s{1,100}Target Domain\s{0,100}:\s{0,100}(?=\w)({target_domain}.+?)\s{1,100}Target Account ID\s{0,100}:\s{0,100}\%\{({target_user_sid}[^}]+)\}""",
      """Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller Domain:\s{1,100}({domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\([^,]+,({logon_id}[^\)]+)"""
      """Caller User Name\s{0,100}:\s{0,100}({user}.+?)\s{1,100}Caller Domain\s{0,100}:\s{0,100}({domain}.+?)\s{1,100}Caller Logon ID\s{0,100}:\s{0,100}\([^,\s]+[,\s]({logon_id}[^\)]+)"""
    ]
    DupFields=["host->dest_host" ]
  }
```