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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\+\d+:\d+)\s({host}[^\s]+)""",
    """({event_name}A logon was attempted using explicit credentials)""",
    """sourceip="({src_ip}[A-Fa-f\d.:]+)"""",
    """EVENT_ID="*({event_code}\d+)""",
    """EVENT_HOST="({host}[^"]+)""",
    """EVENT_USERNAME="(-|({domain}[^\\]+)\\+(-|({user}[^"]+)))""",
    """Logon ID:\s+({logon_id}[^\s]+)\s+Logon GUID"""
    """Subject(:|=)[\s;]*Security ID(:|=)\s*(\\NULL SID|({user_sid}[^=:]*?))[\s;]*Account Name(:|=)""",
    """Subject(:|=)[^"]+?Account Name(:|=)\s*(?:-|SYSTEM|({user}[^\s]*?))[\s;]*Account Domain(:|=)""",
    """Subject(:|=)[^"]+?Account Domain(:|=)\s*(?:-|NT Service|({domain}[^\s]*?))[\s;]*Logon ID(:|=)""",
    """Subject(:|=)[^"]+?Logon ID(:|=)\s*({logon_id}[^=:]*?)[\s;]*Logon GUID(:|=)""",
    """Subject(:|=)[^"]+?Logon GUID(:|=)\s*\{({user_logon_guid}[^}]+)\}[\s;]*Account Whose""",
    """Used(:|=);?\s*Account Name(:|=)\s*({account}[^\s;@]+?)(@({account_domain}[^\s;]+?))?[\s;]*Account Domain(:|=)"""
    """Used(:|=)[^"]+?Account Domain(:|=)\s*(|({account_domain}[^=:]*?))[\s;]*Logon GUID(:|=)""",
    """Used(:|=)[^"]+?Logon GUID(:|=)\s*\{({account_logon_guid}[^=:]*?)\}[\s;]*Target Server(:|=)""",
    """Target Server Name(:|=)\s*({dest_host}[^=:]*?)[\s;]*Additional Information(:|=)""",
    """Additional Information(:|=)\s*({dest_service}[^=:]*?)[\s;]*Process Information(:|=)""",
    """Process ID(:|=)\s*({process_id}[^=:]*?)[\s;]*Process Name(:|=)""",
    """Process Name(:|=)\s*(?:|({process}({directory}(?:[^"]+)?[\\\/])?\s*({process_name}[^\\\/]+?)))\s+Network""",
    """Network Address(:|=)\s*(?:-|({src_ip}[a-fA-F:\d.]+))"""
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
      """"dhn":"({host}[^-"]+)""",
      """({event_code}4648)""",
      """Subject(:|=)[\s;]*Security ID(:|=)\s*({user_sid}.*?)[\s;]*Account Name(:|=)""",
      """Subject(:|=).+?Account Name(:|=)\s*(?:-|SYSTEM|({user}[^\s]*?))[\s;]*Account Domain(:|=)""",
      """Subject(:|=).+?Account Domain(:|=)\s*(?:-|NT Service|({domain}[^\s]*?))[\s;]*Logon ID(:|=)""",
      """Subject(:|=).+?Logon ID(:|=)\s*({logon_id}.*?)[\s;]*Logon GUID(:|=)""",
      """Subject(:|=).+?Logon GUID(:|=)\s*\{({user_logon_guid}[^}]+)\}[\s;]*Account Whose""",
      """Used(:|=);?\s*Account Name(:|=)\s*({account}.*?)[\s;]*Account Domain(:|=)"""
      """Used(:|=).+?Account Domain(:|=)\s*(|({account_domain}.*?))[\s;]*Logon GUID(:|=)""",
      """Used(:|=).+?Logon GUID(:|=)\s*\{({account_logon_guid}.*?)\}[\s;]*Target Server(:|=)""",
      """Target Server Name(:|=)\s*({dest_host}.*?)[\s;]*Additional Information(:|=)""",
      """Additional Information(:|=)\s*({dest_service}.*?)[\s;]*Process Information(:|=)""",
      """Process ID(:|=)\s*({process_id}.*?)[\s;]*Process Name(:|=)""",
      """Process Name(:|=)\s*(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))[\s;]*Network Information(:|=)""",
      """Network Address(:|=)\s*(?:-|({src_ip}[a-fA-F:\d.]+))"""
    ]
    DupFields = ["directory->process_directory"]
  }
```