#### Parser Content
```Java
{
Name = raw-asa-113005
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ "%ASA" , "-113005", " AAA user " ]
  Fields = [ 
    """\w+\s+\d+ \d\d:\d\d:\d\d\s+({host}\S+)\s+%ASA""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """reason\s*=\s*({failure_reason}.+?)\s*:""",
    """server\s*=\s*({dest_ip}[a-fA-F\d.:]+)""",
    """user\s*=\s*(?:|({user}[^:]+))\s+:""",
    """user IP\s*=\s*({src_ip}[a-fA-F\d.:]+)""",
 ]
}
```