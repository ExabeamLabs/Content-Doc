#### Parser Content
```Java
{
Name = powershell-800-syslog-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "powershell-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Windows PowerShell""", """CommandLine=""", """(EventID 800)""", """ScriptName =""", """PowerShell: [""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})\sPowerShell\[""",
    """UserId=({domain}[^\\]{1,2000})\\+({user}[^\s]{1,2000})""",
    """HostApplication=({powershell_image}[^=]{1,2000}?)\s{1,100}\w+=""",
    """ScriptName =\s{0,100}({process}({process_directory}[^\s=]{1,2000}?)({process_name}[^\\=]{0,2000}?))\s{1,100}\w+=""",
    """CommandLine=\s{0,100}(|({command_line}.+?))\s{1,100}\w+:""",
    """Details:[^@]{1,2000}?CommandInvocationParameterBinding[^@]{1,2000}?value="{1,20}\s{0,100}({command_module}[^"]{0,2000}?)\s{0,100}"{1,20}""",
    """Details:[^@]{1,2000}?CommandInvocation\([^\)]{1,2000}\):\s{0,100}\\*"{1,20}\s{0,100}({command_invocation}[^"\\]{1,2000})\s{0,100}""",
    """\(EventID ({event_code}800)"""
  ]


}
```