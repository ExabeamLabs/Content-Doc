#### Parser Content
```Java
{
Name = powershell-800-syslog-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "powershell-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Windows PowerShell""", """CommandLine=""", """(EventID 800)""", """ScriptName=""", """PowerShell: [""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s({host}[^\s]+)\sPowerShell\[""",
    """UserId=({domain}[^\\]+)\\+({user}[^\s]+)""",
    """HostApplication=({powershell_image}[^=]+?)\s+\w+=""",
    """ScriptName=\s*({process}({process_directory}[^\s=]+?)({process_name}[^\\=]*?))\s+\w+=""",
    """CommandLine=\s*(|({command_line}.+?))\s+\w+:""",
    """Details:[^@]+?CommandInvocationParameterBinding[^@]+?value="+\s*({command_module}[^"]*?)\s*"+""",
    """Details:[^@]+?CommandInvocation\([^\)]+\):\s*\\*"+\s*({command_invocation}[^"\\]+)\s*""",
    """\(EventID ({event_code}800)"""
  ]
}
```