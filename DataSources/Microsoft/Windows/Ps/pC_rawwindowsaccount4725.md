#### Parser Content
```Java
{
Name = raw-windows-account-4725
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-account-disabled"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "A user account was disabled" ]
    Fields = [
      """({event_name}A user account was disabled)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """Security(,|\s{1,100})({record_id}[\d]{1,2000})""",
      """({event_code}4725)""",
      """exabeam_host=(gcs-topic|({host}[\w.\-]{1,2000}))""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(\s{1,100}|,)({host}[^,\s\=]{1,2000})""",
      """Information\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}""",
      """({host}[^\/\s]{1,2000})\/Microsoft-Windows-Security-Auditing""",
      """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)""",
      """"system_name":"({host}[^"]{1,2000})"""",
      """Subject:.+?Security ID:\s{1,100}({user_sid}.+?)\s{1,100}Account Name:""",
      """Subject:.+?Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID""",
      """Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
      """Target Account.+?Security ID:\s{0,100}(%\{)?({target_user_sid}.+?)\}?\s{1,100}Account Name:\s{1,100}({target_user}.+?)\s{1,100}Account Domain""",
      """Target Account.+?Account Domain:\s{0,100}(?=\w)(({target_domain}[^\s\^\r\n$",]{1,2000})|)(\s{1,100}[^\^\r\n$])?""",
      """"SubjectUserSid":"({user_sid}[^"]{1,2000})""",
      """"SubjectDomainName":"({domain}[^"]{1,2000})""",
      """"SubjectLogonId":"({logon_id}[^"]{1,2000})""",
      """"SubjectUserName":"({user}[^"]{1,2000})""",
      """"TargetSid":"({target_user_sid}[^"]{1,2000})""",
      """"TargetDomainName":"({target_domain}[^"]{1,2000})""",
      """"TargetUserName":"({target_user}[^"]{1,2000})""",
    ]
    DupFields=[ "host->dest_host" ]
  

}
```