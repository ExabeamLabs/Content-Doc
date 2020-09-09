#### Parser Content
```Java
{
Name = cisco-asa-process-created-1
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-111010", "%ASA-" ]
  Fields = [
    """exabeam_host=(.+?@\s*)?({host}[\w.\-]+)""",
    """({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d)""",
    """%ASA\-({priority}\d+)\-({event_code}\d+)""",
    """User\s+'({user}[^']+)'""",
    """({event_name}executed)\s+'({command_line}[^']+)\s*'""",
    """from IP ({src_ip}[a-fA-F0-9.:]+)"""
  ]
}
```