#### Parser Content
```Java
{
Name = cisco-asa-auth-successful
  Vendor = Cisco
  Product = Adaptive Security Appliance
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-611101", "%ASA-" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]{1,2000}))""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """%ASA\-({priority}\d{1,100})\-({event_code}\d{1,100})""",
    """({time}\w+ \d{1,100} \d{4} \d\d:\d\d:\d\d):\s{0,100}%ASA""",
    """Uname:\s{1,100}(({user_email}[^@\s,"]{1,2000}@[^\.\s,"]{1,2000}\.[^\s,"]{1,2000})|({user}[^\s,"]{1,2000}))""",
    """({event_name}User authentication succeeded)""",
    """IP address:\s{0,100}({src_ip}[a-fA-F0-9.:]{1,2000})"""
  ]


}
```