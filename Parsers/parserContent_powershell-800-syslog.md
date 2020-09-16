#### Parser Content
```Java
{
Name = powershell-800-syslog
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "powershell-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Windows PowerShell""", """PowerShell (800)""", """CommandLine=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)[+-]\S+\s*({host}\S+)\sEvntSLog""",
    """UserId=({domain}.*?)\\+(SYSTEM|({user}.*?))\s+HostName""",
    """Host\s*Application\s*=\s*({powershell_image}[^=]+\.\w+)\s""",
    """ScriptName=\s*({process}({directory}([\w:]+\\)?([^\\=]+?\\)*?)({process_name}[^\\=]*?))\s+CommandLine=""",
    """CommandLine=\s*({command_line}.*?)\s*Details:""",
    """Details:.*?CommandInvocation.*?ParameterBinding.*?value="+\s*({command_module}[^"]*?)\s*"+""",
    """Details:.+?CommandInvocation\(.+?\):\s*\\*"+\s*({command_invocation}[^"\\]+)\s*""",
    """({event_code}800)"""
  ]
}
```