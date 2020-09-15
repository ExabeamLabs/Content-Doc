#### Parser Content
```Java
{
Name = cisco-asa-auth-failed
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-751011", "%ASA-" ]
  Fields = [
    """exabeam_host=(.+?@\s*)?({host}[\w.\-]+)""",
    """({host}[\w\-.]+)\s+({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d):\s*%ASA\-({priority}\d+)\-({event_code}\d+)""",
    """:\s*Local\s*:\s*({src_ip}[a-fA-F\d.:]+):({src_port}\d+)\s""",
    """\sRemote\s*:\s*({dest_ip}[a-fA-F\d.:]+):({dest_port}\d+)\s""",
    """({event_name}Failed user authentication)""",
    """Username\s*:\s*({user}\S+)""",
    """\sError\s*:\s*({failure_reason}.+?)\s*$"""
  ]
}
```