#### Parser Content
```Java
{
Name = raw-asa-113004-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "%ASA" , "-113004", "AAA user ", " Successful" ]
  Fields = [ 
    """exabeam_raw=.*?({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """({time}\w{3} \d\d \d{4} \d\d:\d\d:\d\d)""",
    """exabeam_host=(::ffff:)?({host}[^\s,"]+)""",
    """exabeam_host=(::ffff:)?(.+?@\s*)?({host}[^\s,"]+)""",
    """\d\d:\d\d:\d\d\s+(::ffff:)?({host}[^\s]+)\s*:?""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s+(::ffff:)?({host}\S+)\s+:?\s*%ASA""",
    """user\s*=\s*({user_email}[^@\s"]+@[^@\s"]+)""",
    """user\s*=\s*(?![^\s]+@[^\s]+)(({domain}[^\s\\"]+)\\+)?({user}[^@\s\\"\.]+)\s""",
    """user\s*=\s*({user_firstname}\w+)\.({user_lastname}\w+)""",
    """user\s*=\s*({user}[^"\s]+)""", 
    """server\s*=\s*(::ffff:)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    """\%ASA-\d+-({event_code}\d+)[:\s]+({event_name}[^:]+)\s"""
 ]
 DupFields = ["user->account"]
}
```