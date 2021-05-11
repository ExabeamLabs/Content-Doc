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
    """exabeam_host=([^=@]+@\s{0,100})?({host}\S+)""",
    """"TimeGenerated":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"""
    """Computer"{1,20}:"{1,20}({host}[^"]+)""",
    """Machine"{1,20}:"{1,20}({src_host}[^"]+)""",
    """ExecutableName"{1,20}:"{1,20}({process_name}[^"]+)""",
    """FirstPid"{1,20}:({pid}\d{1,100})""",
    """ExecutablePath"{1,20}:"{1,20}({process_directory}[^.]+)\\({process}.+?)"{1,20}"""
    """CommandLine"{1,20}:"{1,20}({command_line}[^"]+)"{1,20}"""
    """UserName"{1,20}:"{1,20}(SYSTEM|({user}[^"]+))"""
    """UserDomain"{1,20}:"{1,20}({domain}[^"]+)"""
    ]
}
```