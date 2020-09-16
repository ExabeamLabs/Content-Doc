#### Parser Content
```Java
{
Name = powershell-800
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "powershell-activity"
  TimeFormat = "YYYY-DD-MM'T'HH:mm:ss"
  Conditions = [ """<Provider Name='PowerShell""", """800</EventID>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d+Z'/>""",
    """<Computer>({host}.*?)</Computer>""",
    """UserId=({domain}.*?)\\({user}.*?)\s+HostName""",
    """Host\s*Application\s*=\s*({powershell_image}[^\s]+)\s+EngineVersion""",
    """ScriptName=\s*({process}({directory}([\w:]+\\)?([^\\]+?\\)*?)({process_name}[^\\]*?))\s+CommandLine""",
    """CommandLine=({command_line}[^<]+)</Data>""",
    """Details:.+?CommandInvocation.+?ParameterBinding.+?value=\\"(function\s)?({command_module}[^\s\\,"]+)""",
    """Details:.+?CommandInvocation\(.+?\):\s*\\*"({command_invocation}[^"\\]+)""",
    """({event_code}800)"""
  ]
}
```