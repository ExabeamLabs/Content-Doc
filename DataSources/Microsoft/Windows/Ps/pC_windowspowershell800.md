#### Parser Content
```Java
{
Name = windows-powershell-800
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "powershell-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """PowerShell""", """EventID: 800""", """HostApplication""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-\.]{1,2000}) PowerShell""",
    """({event_code}800)""",
    """UserId=({domain}[^\\]{1,2000})\\({user}[^\s]{1,2000}?)\s{1,100}HostName""",
    """HostApplication=\s{0,100}({powershell_image}\S{1,2000}?)\s{1,100}""",
    """CommandLine=\s{0,100}({command_line}\S[^<]{1,2000}?)\s{1,100}(?:\{\s{1,100})?Details:""",
    """CommandInvocation[^:]{1,2000}:\s{0,100}"({command_invocation}[^"]{1,2000})"""",
    """CommandInvocation[^<]{0,2000}?value="\s{0,100}(|-|({command_module}[^"]{1,2000}?))\s{0,100}"\s{0,100}"""

    ]


}
```