#### Parser Content
```Java
{
Name = powershell-800
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "powershell-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<Provider Name='PowerShell""", """800</EventID>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z'/>""",
    """<Computer>({host}[^<]+)</Computer>""",
    """UserId=({domain}[^\\]+)\\({user}[^\s]+?)\s{1,100}HostName""",
    """Host\s{0,100}Application\s{0,100}=\s{0,100}({powershell_image}[^\s]+)\s{1,100}EngineVersion""",
    """ScriptName=\s{0,100}(|({process}({directory}([\w:]+\\)?([^\\]+?\\)*?)({process_name}[^\\=]*?)))\s{1,100}CommandLine""",
    """CommandLine=\s{0,100}({command_line}[^<]+?)\s{0,100}</Data>""",
    """Details:.+?CommandInvocation.+?ParameterBinding.+?value=\\"(function\s)?({command_module}[^\s\\,"]+)""",
    """Details:.+?CommandInvocation\(.+?\):\s{0,100}\\*"({command_invocation}[^"\\]+)""",
    """({event_code}800)"""
  ]
}
```