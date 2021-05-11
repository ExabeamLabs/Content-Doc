#### Parser Content
```Java
{
Name = powershell-800-syslog
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "powershell-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Windows PowerShell""", """PowerShell (800)""", """CommandLine=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)[+-]\S+\s{0,100}({host}\S+)\sEvntSLog""",
    """UserId=({domain}.*?)\\+(SYSTEM|({user}.*?))\s{1,100}HostName""",
    """Host\s{0,100}Application\s{0,100}=\s{0,100}({powershell_image}[^=]+\.\w+)\s""",
    """ScriptName=\s{0,100}({process}({directory}([\w:]+\\)?([^\\=]+?\\)*?)({process_name}[^\\=]*?))\s{1,100}CommandLine=""",
    """CommandLine=\s{0,100}({command_line}.*?)\s{0,100}Details:""",
    """Details:.*?CommandInvocation.*?ParameterBinding.*?value="{1,20}\s{0,100}({command_module}[^"]*?)\s{0,100}"{1,20}""",
    """Details:.+?CommandInvocation\(.+?\):\s{0,100}\\*"{1,20}\s{0,100}({command_invocation}[^"\\]+)\s{0,100}""",
    """({event_code}800)"""
  ]
}
```