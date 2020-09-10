#### Parser Content
```Java
{
Name = cisco-asa-auth-successful
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-611101", "%ASA-" ]
  Fields = [
    """exabeam_host=(.+?@\s*)?({host}[\w.\-]+)""",
    """({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d):\s*%ASA\-({priority}\d+)\-({event_code}\d+)""",
    """Uname:\s+({user}[^\s,]+)""",
    """({event_name}User authentication succeeded)""",
    """IP address:\s*({src_ip}[a-fA-F0-9.:]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```