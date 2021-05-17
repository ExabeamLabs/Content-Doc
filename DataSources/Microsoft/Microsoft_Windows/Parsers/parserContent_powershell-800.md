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
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """UserId=({domain}[^\\]{1,2000})\\({user}[^\s]{1,2000}?)\s{1,100}HostName""",
    """Host\s{0,100}Application\s{0,100}=\s{0,100}({powershell_image}[^\s]{1,2000})\s{1,100}EngineVersion""",
    """ScriptName=\s{0,100}(|({process}({directory}([\w:]{1,2000}\\)?([^\\]{1,2000}?\\)*?)({process_name}[^\\=]{0,2000}?)))\s{1,100}CommandLine""",
    """CommandLine=\s{0,100}({command_line}[^<]{1,2000}?)\s{0,100}</Data>""",
    """Details:.+?CommandInvocation.+?ParameterBinding.+?value=\\"(function\s)?({command_module}[^\s\\,"]{1,2000})""",
    """Details:.+?CommandInvocation\(.+?\):\s{0,100}\\*"({command_invocation}[^"\\]{1,2000})""",
    """({event_code}800)"""
  ]
}
```