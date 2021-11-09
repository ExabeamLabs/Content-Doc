#### Parser Content
```Java
{
Name = azure-process-created-1
  Vendor = Microsoft
  Product = Azure
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Type":"VMProcess"""", """ExecutableName""" ]
  Fields = [
    """exabeam_host=([^=@]{1,2000}@\s{0,100})?({host}\S+)""",
    """"TimeGenerated":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"""
    """Computer"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """Machine"{1,20}:"{1,20}({src_host}[^"]{1,2000})""",
    """ExecutableName"{1,20}:"{1,20}({process_name}[^"]{1,2000})""",
    """FirstPid"{1,20}:({pid}\d{1,100})""",
    """"ExecutablePath":"({process}((|({directory}[^"]{0,2000}?))[\\\/]{1,20})?({process_name}[^"\\\/]{1,2000}?))\s{0,100}""""
    """CommandLine":"\s{0,100}({command_line}[^\n]{1,2000}?)\s{0,100}","\w{1,100}""""
    """UserName"{1,20}:"{1,20}((?i)SYSTEM|({user}[^"]{1,2000}))"""
    """UserDomain"{1,20}:"{1,20}({domain}[^"]{1,2000})"""
    ]
    DupFields = [ "directory->process_directory" ]
}
}
```