#### Parser Content
```Java
{
Name = windows-xml-powershell-800
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "powershell-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<Provider Name ='PowerShell""", """>800</EventID>""", """<Computer>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """UserId=({domain}[^\\]{1,2000})\\({user}[^\s]{1,2000}?)\s{1,100}HostName""",
    """({event_code}800)"""
    """ScriptName =\s{0,100}(|({process}({directory}([^\\]{1,2000}?\\)*?)({process_name}[^\\=]{0,2000}?)))\s{1,100}CommandLine""",
    """HostApplication=\s{0,100}({powershell_image}[^=]{1,2000}?)\s{1,100}EngineVersion=""",
    """CommandLine=\s{0,100}({command_line}[^<]{1,2000}?)\s{0,100}<\/Data>""",
    """<Data>CommandInvocation[^<]{0,10000}value="{1,200}\s{0,100}(|-|({command_module}.+?))\s{0,100}"\s{0,100}<\/Data>""",
    """<Data>CommandInvocation[^:]{1,2000}:\s{0,100}"{1,100}({command_invocation}[^"]{1,2000})"""
    ]
    DupFields = ["directory->process_directory"]


}
```