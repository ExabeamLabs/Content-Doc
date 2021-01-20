#### Parser Content
```Java
{
Name = raw-asa-113004-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ "%ASA" , "-113004", "AAA user " ]
  Fields = [ 
    """exabeam_raw=.*?({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s,"]+)""",
    """exabeam_host=(.+?@\s*)?({host}[^\s,"]+)""",
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s*:""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s+({host}\S+)\s+:?\s*%ASA""",
    """user\s*=\s*({user_email}[^@\s"]+@[^@\s"]+)""",
    """user\s*=\s*(?![^\s]+@[^\s]+)(({domain}[^\s\\"]+)\\+)?({user}[^@\s\\"\.]+)\s""",
    """user\s*=\s*({user_firstname}\w+)\.({user_lastname}\w+)""",
    """user\s*=\s*({user}[^"\s]+)""", 
    """server\s*=\s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
 ]
 DupFields = ["user->account"]
}
```