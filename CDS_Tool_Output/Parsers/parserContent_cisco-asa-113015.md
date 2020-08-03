#### Parser Content
```Java
{
Name = cisco-asa-113015
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-113015", "%ASA-" ]
  Fields = [
    """({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)\s+({host}.+?)\s*:\s*%ASA-({priority}\d+)-({event_code}\d+)""",
    """({event_name}AAA user authentication Rejected)""",
    """\sreason\s*=\s*({failure_reason}.+?)\s*:""",
    """\suser\s*=\s*({user}.+?)\s*:""",
    """\suser IP\s*=\s*({src_ip}[a-fA-F\d.:]+)""",
  ]
}
```