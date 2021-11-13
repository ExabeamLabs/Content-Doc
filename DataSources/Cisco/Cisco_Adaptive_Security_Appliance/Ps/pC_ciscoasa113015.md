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
    """({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)\s{1,100}({host}.+?)\s{0,100}:\s{0,100}%ASA-({priority}\d{1,100})-({event_code}\d{1,100})""",
    """({event_name}AAA user authentication Rejected)""",
    """\sreason\s{0,100}=\s{0,100}({failure_reason}.+?)\s{0,100}:""",
    """\suser\s{0,100}=\s{0,100}({user}.+?)\s{0,100}:""",
    """\suser IP\s{0,100}=\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
  ]


}
```