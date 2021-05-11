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
      """<Computer>({host}[^<]+)</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s{0,100}"?({host}.+?)("|\s|;)""",
      """({event_code}4648)""",
      """Subject(:|=)[\s;]*Security ID(:|=)\s{0,100}({user_sid}[^\s;]+?)[\s;]*Account Name(:|=)""",
      """Subject(:|=)[^"]+?Account Name(:|=)\s{0,100}(?:-|SYSTEM|({user}[^\s;]+?))[\s;]*Account Domain(:|=)""",
      """Subject(:|=)[^"]+?Account Domain(:|=)\s{0,100}(?:-|NT Service|({domain}[^\s;]+?))[\s;]*Logon ID(:|=)""",
      """Subject(:|=)[^"]+?Logon ID(:|=)\s{0,100}({logon_id}[^=:]+?)[\s;]*Logon GUID(:|=)""",
      """Subject(:|=)[^"]+?Logon GUID(:|=)\s{0,100}\{({user_logon_guid}[^}]+)\}[\s;]*Account Whose""",
      """Used(:|=);?\s{0,100}Account Name(:|=)\s{0,100}({account}[^\s;@]+?)(@({account_domain}[^\s;]+?))?[\s;]*Account Domain(:|=)"""
      """Used(:|=)[^"]+?Account Domain(:|=)\s{0,100}((?i)(NULL)|({account_domain}[^\s;]+?))[\s;]*Logon GUID(:|=)""",
      """Used(:|=)[^"]+?Logon GUID(:|=)\s{0,100}\{({account_logon_guid}[^\s;]+?)\}[\s;]*Target Server(:|=)""",
      """Target Server Name(:|=)\s{0,100}({dest_host}[^\s;]+?)(:\S+)?[\s;]*Additional Information(:|=)""",
      """Additional Information(:|=)\s{0,100}({dest_service}[^=:]+?)[\s;]*Process Information(:|=)""",
      """Process ID(:|=)\s{0,100}({process_id}[^=:]+?)[\s;]*Process Name(:|=)""",
      """Process Name(:|=)\s{0,100}(?:|({process}({directory}(?:[^"]+)?[\\\/])?\s{0,100}({process_name}[^\\\/]+?)))\s{1,100}Network""",
      """Network Address(:|=)\s{0,100}(?:-|({src_ip}[a-fA-F:\d.]+))"""
    ]
    DupFields = ["directory->process_directory"]
  }
```