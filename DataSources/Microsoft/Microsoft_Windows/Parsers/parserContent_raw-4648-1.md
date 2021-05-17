#### Parser Content
```Java
{
Name = raw-4648-1
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-account-switch"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["A logon was attempted using explicit credentials", "Target Server Name", "dhn"]
    Fields = [
      """({event_name}A logon was attempted using explicit credentials)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"dhn":"({host}[^-"]{1,2000})""",
      """({event_code}4648)""",
      """Subject(:|=)[\s;]{0,2000}Security ID(:|=)\s{0,100}({user_sid}.*?)[\s;]{0,2000}Account Name(:|=)""",
      """Subject(:|=).+?Account Name(:|=)\s{0,100}(?:-|SYSTEM|({user}[^\s]{0,2000}?))[\s;]{0,2000}Account Domain(:|=)""",
      """Subject(:|=).+?Account Domain(:|=)\s{0,100}(?:-|NT Service|({domain}[^\s]{0,2000}?))[\s;]{0,2000}Logon ID(:|=)""",
      """Subject(:|=).+?Logon ID(:|=)\s{0,100}({logon_id}.*?)[\s;]{0,2000}Logon GUID(:|=)""",
      """Subject(:|=).+?Logon GUID(:|=)\s{0,100}\{({user_logon_guid}[^}]{1,2000})\}[\s;]{0,2000}Account Whose""",
      """Used(:|=);?\s{0,100}Account Name(:|=)\s{0,100}({account}.*?)[\s;]{0,2000}Account Domain(:|=)"""
      """Used(:|=).+?Account Domain(:|=)\s{0,100}(|({account_domain}.*?))[\s;]{0,2000}Logon GUID(:|=)""",
      """Used(:|=).+?Logon GUID(:|=)\s{0,100}\{({account_logon_guid}.*?)\}[\s;]{0,2000}Target Server(:|=)""",
      """Target Server Name(:|=)\s{0,100}({dest_host}.*?)[\s;]{0,2000}Additional Information(:|=)""",
      """Additional Information(:|=)\s{0,100}({dest_service}.*?)[\s;]{0,2000}Process Information(:|=)""",
      """Process ID(:|=)\s{0,100}({process_id}.*?)[\s;]{0,2000}Process Name(:|=)""",
      """Process Name(:|=)\s{0,100}(?: |({process}({directory}(?:[^";]{1,2000})?[\\\/])?({process_name}[^\\\/";]{1,2000}?)))[\s;]{0,2000}Network Information(:|=)""",
      """Network Address(:|=)\s{0,100}(?:-|({src_ip}[a-fA-F:\d.]{1,2000}))"""
    ]
    DupFields = ["directory->process_directory"]
  }
```