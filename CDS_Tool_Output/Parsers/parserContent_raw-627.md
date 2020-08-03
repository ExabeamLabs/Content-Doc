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
      """({time}\w+ \d{1,2} [\d:]+ \d+)""",
      """Security,({record_id}\d+)""",
      """\sType=({outcome}.+?)\s+\w+=""",
      """exabeam_host=({host}[\w.\-]+)""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(,|\s)({host}[\w\-.]+)""",
      """({host}[\w\-.]+)\/Security""",
      """Computer=({host}[\w\-.]+)""",
      """\s+({outcome}(?i)((audit|success|failure)( |_)(success|audit|failure)))\s+""",
      """({event_code}627)""",
      """Target Account Name\s*:\s*(?=\w)({target_user}.+?)\s+Target Domain\s*:\s*(?=\w)({target_domain}.+?)\s+Target Account ID\s*:\s*\%\{({target_user_sid}[^}]+)\}""",
      """Caller User Name:\s+({user}.+?)\s+Caller Domain:\s+({domain}.+?)\s+Caller Logon ID:\s+\([^,]+,({logon_id}[^\)]+)"""
      """Caller User Name\s*:\s*({user}.+?)\s+Caller Domain\s*:\s*({domain}.+?)\s+Caller Logon ID\s*:\s*\([^,\s]+[,\s]({logon_id}[^\)]+)"""
    ]
    DupFields=["host->dest_host" ]
  }
```