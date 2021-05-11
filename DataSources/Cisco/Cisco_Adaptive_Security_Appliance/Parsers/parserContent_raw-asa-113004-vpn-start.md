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
    """exabeam_raw=.*?({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
    """({time}\w{3} \d\d \d{4} \d\d:\d\d:\d\d)""",
    """exabeam_host=(::ffff:)?({host}[^\s,"]+)""",
    """exabeam_host=(::ffff:)?(.+?@\s{0,100})?({host}[^\s,"]+)""",
    """\d\d:\d\d:\d\d\s{1,100}(::ffff:)?({host}[^\s]+)\s{0,100}:?""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s{1,100}(::ffff:)?({host}\S+)\s{1,100}:?\s{0,100}%ASA""",
    """user\s{0,100}=\s{0,100}({user_email}[^@\s"]+@[^@\s"]+)""",
    """user\s{0,100}=\s{0,100}(?![^\s]+@[^\s]+)(({domain}[^\s\\"]+)\\+)?({user}[^@\s\\"\.]+)\s""",
    """user\s{0,100}=\s{0,100}({user_firstname}\w+)\.({user_lastname}\w+)""",
    """user\s{0,100}=\s{0,100}({user}[^"\s]+)""", 
    """server\s{0,100}=\s{0,100}(::ffff:)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    """\%ASA-\d{1,100}-({event_code}\d{1,100})[:\s]+({event_name}[^:]+)\s"""
 ]
 DupFields = ["user->account"]
}
```