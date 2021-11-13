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
    """exabeam_host=(.+?@\s{0,100})?({host}[\w.\-]{1,2000})""",
    """({host}[\w\-.]{1,2000})\s{1,100}({time}\w+ \d{1,100} \d{4} \d\d:\d\d:\d\d):\s{0,100}%ASA\-({priority}\d{1,100})\-({event_code}\d{1,100})""",
    """:\s{0,100}Local\s{0,100}:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000}):({src_port}\d{1,100})\s""",
    """\sRemote\s{0,100}:\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000}):({dest_port}\d{1,100})\s""",
    """({event_name}Failed user authentication)""",
    """Username\s{0,100}:\s{0,100}({user}\S+)""",
    """\sError\s{0,100}:\s{0,100}({failure_reason}.+?)\s{0,100}$"""
  ]


}
```