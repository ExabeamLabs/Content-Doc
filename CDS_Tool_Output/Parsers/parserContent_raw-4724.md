#### Parser Content
```Java
{
Name = raw-4724
    Vendor = Microsoft 
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-password-reset"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "An attempt was made to reset an account's password" ]
    Fields = [
      """({event_name}An attempt was made to reset an account's password)""",
      """Security,?\s*(rn=)?({record_id}[\d]+)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(,|\s+)({host}[\w\-\.]+)""",
      """({host}[\w.\-]+)\s*:\s+An attempt was made to reset an account's password""",
      """({event_code}4724)""",
      """({host}[^\/\s]+)\/Microsoft-Windows-Security-Auditing""",
      """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
      """Computer : ({host}[\w\-]+)""",
      """Subject:.+?Security ID:\s+({user_sid}.+?)\s+Account Name:""",
      """\s*Source Address:\s*(?:-|({src_ip}[^\s]+))\s*Source Port:""",
      """Subject:.+?Account Name:\s+({user}.+?)\s+Account Domain:\s+({domain}.+?)\s+Logon ID""",
      """Logon ID:\s+({logon_id}[^\s]+)""",
      """Target Account.+?Security ID:\s+(?:|({target_user_sid}.+?))\s+Account Name:\s+(?:|({target_user}.+?))\s+Account Domain:\s+({target_domain}[^",\s]+)"""
    ]
    DupFields=[ "host->dest_host" ]
  }
```