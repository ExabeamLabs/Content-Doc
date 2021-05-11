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
      """Security(,|\s{1,100})({record_id}[\d]+)""",
      """({event_code}4725)""",
      """exabeam_host=({host}[\w.\-]+)""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(\s{1,100}|,)({host}[^,\s\=]+)""",
      """Information\s{1,100}({host}[\w.\-]+)\s{1,100}""",
      """({host}[^\/\s]+)\/Microsoft-Windows-Security-Auditing""",
      """Computer(\w+)?["\s]*(:|=)\s{0,100}"?({host}.+?)("|\s)""",
      """"system_name":"({host}[^"]+)"""",
      """Subject:.+?Security ID:\s{1,100}({user_sid}.+?)\s{1,100}Account Name:""",
      """Subject:.+?Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID""",
      """Logon ID:\s{1,100}({logon_id}[^\s]+)""",
      """Target Account.+?Security ID:\s{0,100}(%\{)?({target_user_sid}.+?)\}?\s{1,100}Account Name:\s{1,100}({target_user}.+?)\s{1,100}Account Domain""",
      """Target Account.+?Account Domain:\s{0,100}(?=\w)(({target_domain}[^\s\^\r\n$",]+)|)(\s{1,100}[^\^\r\n$])?""",
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