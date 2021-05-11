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
    """HostApplication=({powershell_image}[^=]+?)\s{1,100}\w+=""",
    """ScriptName=\s{0,100}({process}({process_directory}[^\s=]+?)({process_name}[^\\=]*?))\s{1,100}\w+=""",
    """CommandLine=\s{0,100}(|({command_line}.+?))\s{1,100}\w+:""",
    """Details:[^@]+?CommandInvocationParameterBinding[^@]+?value="{1,20}\s{0,100}({command_module}[^"]*?)\s{0,100}"{1,20}""",
    """Details:[^@]+?CommandInvocation\([^\)]+\):\s{0,100}\\*"{1,20}\s{0,100}({command_invocation}[^"\\]+)\s{0,100}""",
    """\(EventID ({event_code}800)"""
  ]
}
```