#### Parser Content
```Java
{
Name = xml-4648
    Vendor = Microsoft
    Product = Windows
    Lms = Splunk
    DataType = "windows-account-switch"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""<EventID>4648</EventID>""", """='ProcessName'"""]
    Fields = [
      """SystemTime(\\)?=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """<Computer>({host}[^<]{1,2000})</Computer>""",
      """<EventID>({event_code}\d{1,100})</EventID>""",
      """<Data Name(\\)?='SubjectUserSid'>({user_sid}[^<]{1,2000})<\/Data>""",
      """<Data Name(\\)?='SubjectUserName'>(-|({user}[^<]{1,2000}))</Data>""",
      """<Data Name(\\)?='SubjectDomainName'>(-|({domain}[^<]{1,2000}))</Data>""",
      """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]{1,2000})</Data>""",
      """<Data Name(\\)?='TargetUserName'>({account}[^<]{1,2000}?)\s{0,100}</Data>""",
      """<Data Name(\\)?='TargetDomainName'>({account_domain}[^<]{1,2000})</Data>""",
      """<Data Name(\\)?='TargetServerName'>({dest_host}[\w\-]{1,2000})[^<]{0,2000}</Data>""",
      """<Data Name(\\)?='ProcessId'>({process_id}[^<]{1,2000})</Data>""",
      """<Data Name(\\)?='ProcessName'>({process}({directory}(?:[^<]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?))<\/Data>""",
      """<Data Name(\\)?='IpAddress'>({src_ip}[a-fA-F:\d.]{1,2000})</Data>""",
      """<Data Name(\\)?='TargetInfo'>({dest_service}[^<]{1,2000})</Data>"""
    ]
    DupFields = ["directory->process_directory"]
  },  
{
    Name = raw-4648-3
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-account-switch"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["""A logon was attempted using explicit credentials""", """Target Server Name""", """Computer"""]
    Fields = [
      """({event_name}A logon was attempted using explicit credentials)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
      """<Computer>({host}[^<]{1,2000})</Computer>""",
      """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s|;)""",
      """({event_code}4648)""",
      """Subject(:|=)[\s;]{0,2000}Security ID(:|=)\s{0,100}({user_sid}[^\s;]{1,2000}?)[\s;]{0,2000}Account Name(:|=)""",
      """Subject(:|=)[^"]{1,2000}?Account Name(:|=)\s{0,100}(?:-|SYSTEM|({user}[^\s;]{1,2000}?))[\s;]{0,2000}Account Domain(:|=)""",
      """Subject(:|=)[^"]{1,2000}?Account Domain(:|=)\s{0,100}(?:-|NT Service|({domain}[^\s;]{1,2000}?))[\s;]{0,2000}Logon ID(:|=)""",
      """Subject(:|=)[^"]{1,2000}?Logon ID(:|=)\s{0,100}({logon_id}[^=:]{1,2000}?)[\s;]{0,2000}Logon GUID(:|=)""",
      """Subject(:|=)[^"]{1,2000}?Logon GUID(:|=)\s{0,100}\{({user_logon_guid}[^}]{1,2000})\}[\s;]{0,2000}Account Whose""",
      """Used(:|=);?\s{0,100}Account Name(:|=)\s{0,100}({account}[^\s;@]{1,2000}?)(@({account_domain}[^\s;]{1,2000}?))?[\s;]{0,2000}Account Domain(:|=)"""
      """Used(:|=)[^"]{1,2000}?Account Domain(:|=)\s{0,100}((?i)(NULL)|({account_domain}[^\s;]{1,2000}?))[\s;]{0,2000}Logon GUID(:|=)""",
      """Used(:|=)[^"]{1,2000}?Logon GUID(:|=)\s{0,100}\{({account_logon_guid}[^\s;]{1,2000}?)\}[\s;]{0,2000}Target Server(:|=)""",
      """Target Server Name(:|=)\s{0,100}({dest_host}[^\s;]{1,2000}?)(:\S+)?[\s;]{0,2000}Additional Information(:|=)""",
      """Additional Information(:|=)\s{0,100}({dest_service}[^=:]{1,2000}?)[\s;]{0,2000}Process Information(:|=)""",
      """Process ID(:|=)\s{0,100}({process_id}[^=:]{1,2000}?)[\s;]{0,2000}Process Name(:|=)""",
      """Process Name(:|=)\s{0,100}(?:|({process}({directory}(?:[^"]{1,2000})?[\\\/])?\s{0,100}({process_name}[^\\\/]{1,2000}?)))\s{1,100}Network""",
      """Network Address(:|=)\s{0,100}(?:-|({src_ip}[a-fA-F:\d.]{1,2000}))"""
    ]
    DupFields = ["directory->process_directory"]
  }
```