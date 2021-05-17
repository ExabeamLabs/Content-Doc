#### Parser Content
```Java
{
Name = raw-4648-3
    Vendor = Microsoft
    Product = Microsoft Windows
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