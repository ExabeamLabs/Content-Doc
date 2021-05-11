#### Parser Content
```Java
{
Name = cisco-ftd-process-created
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-111008", "%FTD-" ]
  Fields = [
    """({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)\s{1,100}({host}[\w\-.]+)\s{0,100}:\s{0,100}%FTD""",
    """%FTD\-({priority}\d{1,100})\-({event_code}\d{1,100})""",
    """User\s{1,100}'({user}[^']+)'""",
    """({event_name}executed)\s{1,100}the\s{1,100}'({command_line}[^']+?)\s{0,100}'"""
  ]
}
```