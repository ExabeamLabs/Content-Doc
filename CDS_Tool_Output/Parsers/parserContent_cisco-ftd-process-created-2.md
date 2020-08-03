#### Parser Content
```Java
{
Name = cisco-ftd-process-created-2
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-111010", "%FTD-" ]
  Fields = [
    """({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)\s+({host}[\w\-.]+)\s*:\s*%FTD""",
    """%FTD\-({priority}\d+)\-({event_code}\d+)""",
    """User\s+'({user}[^']+)'""",
    """({event_name}executed)\s+'({command_line}[^']+?)\s*'""",
    """from IP (0.0.0.0|({src_ip}[A-Fa-f:\d.]+))"""
  ]
}
```