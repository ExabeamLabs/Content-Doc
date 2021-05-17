#### Parser Content
```Java
{
Name = syslog-4648
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss+SS:SS"
  Conditions = [ """EVENT_ID="4648"""", """EVENT_TASK="Logon"""", """A logon was attempted using explicit credentials""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\+\d{1,100}:\d{1,100})\s({host}[^\s]{1,2000})""",
    """({event_name}A logon was attempted using explicit credentials)""",
    """sourceip="({src_ip}[A-Fa-f\d.:]{1,2000})"""",
    """EVENT_ID="{0,20}({event_code}\d{1,100})""",
    """EVENT_HOST="({host}[^"]{1,2000})""",
    """EVENT_USERNAME="(-|({domain}[^\\]{1,2000})\\+(-|({user}[^"]{1,2000})))""",
    """Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})\s{1,100}Logon GUID"""
    """Subject(:|=)[\s;]{0,2000}Security ID(:|=)\s{0,100}(\\NULL SID|({user_sid}[^=:]{0,2000}?))[\s;]{0,2000}Account Name(:|=)""",
    """Subject(:|=)[^"]{1,2000}?Account Name(:|=)\s{0,100}(?:-|SYSTEM|({user}[^\s]{0,2000}?))[\s;]{0,2000}Account Domain(:|=)""",
    """Subject(:|=)[^"]{1,2000}?Account Domain(:|=)\s{0,100}(?:-|NT Service|({domain}[^\s]{0,2000}?))[\s;]{0,2000}Logon ID(:|=)""",
    """Subject(:|=)[^"]{1,2000}?Logon ID(:|=)\s{0,100}({logon_id}[^=:]{0,2000}?)[\s;]{0,2000}Logon GUID(:|=)""",
    """Subject(:|=)[^"]{1,2000}?Logon GUID(:|=)\s{0,100}\{({user_logon_guid}[^}]{1,2000})\}[\s;]{0,2000}Account Whose""",
    """Used(:|=);?\s{0,100}Account Name(:|=)\s{0,100}({account}[^\s;@]{1,2000}?)(@({account_domain}[^\s;]{1,2000}?))?[\s;]{0,2000}Account Domain(:|=)"""
    """Used(:|=)[^"]{1,2000}?Account Domain(:|=)\s{0,100}(|({account_domain}[^=:]{0,2000}?))[\s;]{0,2000}Logon GUID(:|=)""",
    """Used(:|=)[^"]{1,2000}?Logon GUID(:|=)\s{0,100}\{({account_logon_guid}[^=:]{0,2000}?)\}[\s;]{0,2000}Target Server(:|=)""",
    """Target Server Name(:|=)\s{0,100}({dest_host}[^=:]{0,2000}?)[\s;]{0,2000}Additional Information(:|=)""",
    """Additional Information(:|=)\s{0,100}({dest_service}[^=:]{0,2000}?)[\s;]{0,2000}Process Information(:|=)""",
    """Process ID(:|=)\s{0,100}({process_id}[^=:]{0,2000}?)[\s;]{0,2000}Process Name(:|=)""",
    """Process Name(:|=)\s{0,100}(?:|({process}({directory}(?:[^"]{1,2000})?[\\\/])?\s{0,100}({process_name}[^\\\/]{1,2000}?)))\s{1,100}Network""",
    """Network Address(:|=)\s{0,100}(?:-|({src_ip}[a-fA-F:\d.]{1,2000}))"""
    ]
    DupFields = ["directory->process_directory"]
 
}  

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