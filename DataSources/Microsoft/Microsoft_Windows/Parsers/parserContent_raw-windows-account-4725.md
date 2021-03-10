#### Parser Content
```Java
{
Name = raw-windows-account-4725
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-account-disabled"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "A user account was disabled" ]
    Fields = [
      """({event_name}A user account was disabled)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """Security,({record_id}[\d]+),""",
      """({event_code}4725)""",
      """exabeam_host=({host}[\w.\-]+)""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(\s+|,)({host}[^,\s\=]+)""",
      """Information\s+({host}[\w.\-]+)\s+""",
      """({host}[^\/\s]+)\/Microsoft-Windows-Security-Auditing""",
      """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
      """"system_name":"({host}[^"]+)"""",
      """Subject:.+?Security ID:\s+({user_sid}.+?)\s+Account Name:""",
      """Subject:.+?Account Name:\s+({user}.+?)\s+Account Domain:\s+({domain}.+?)\s+Logon ID""",
      """Logon ID:\s+({logon_id}[^\s]+)""",
      """Target Account.+?Security ID:\s*(%\{)?({target_user_sid}.+?)\}?\s+Account Name:\s+({target_user}.+?)\s+Account Domain""",
      """Target Account.+?Account Domain:\s*(?=\w)(({target_domain}[^\s\^\r\n$",]+)|)(\s+[^\^\r\n$])?""",
      """"SubjectUserSid":"({user_sid}[^"]+)""",
      """"SubjectDomainName":"({domain}[^"]+)""",
      """"SubjectLogonId":"({logon_id}[^"]+)""",
      """"SubjectUserName":"({user}[^"]+)""",
      """"TargetSid":"({target_user_sid}[^"]+)""",
      """"TargetDomainName":"({target_domain}[^"]+)""",
      """"TargetUserName":"({target_user}[^"]+)""",
    ]
    DupFields=[ "host->dest_host" ]
  }
```