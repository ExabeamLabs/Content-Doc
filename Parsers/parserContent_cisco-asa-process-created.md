#### Parser Content
```Java
{
Name = cisco-asa-process-created
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-111008", "%ASA-" ]
  Fields = [
    """exabeam_host=(::ffff:)?(.+?@\s*)?({host}[\w.\-]+)""",
    """({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d)""",
    """%ASA\-({priority}\d+)\-({event_code}\d+)""",
    """User\s+'({user}[^']+)'""",
    """({event_name}executed)\s+the\s+'({command_line}[^']+)\s*'"""
  ]
}
```