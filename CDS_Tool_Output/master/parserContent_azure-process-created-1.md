#### Parser Content
```Java
{
Name = azure-process-created-1
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Type":"VMProcess"""", """ExecutableName""" ]
  Fields = [
    """exabeam_host=([^=@]+@\s*)?({host}\S+)""",
    """"TimeGenerated":"({time}\d+-\d+-\d+T\d+:\d+:\d+)"""
    """Computer"+:"+({host}[^"]+)""",
    """Machine"+:"+({src_host}[^"]+)""",
    """ExecutableName"+:"+({process_name}[^"]+)""",
    """FirstPid"+:({pid}\d+)""",
    """ExecutablePath"+:"+({process_directory}[^.]+)\\({process}.+?)"+"""
    """CommandLine"+:"+({command_line}[^"]+)"+"""
    """UserName"+:"+(SYSTEM|({user}[^"]+))"""
    """UserDomain"+:"+({domain}[^"]+)"""
    ]
}
```