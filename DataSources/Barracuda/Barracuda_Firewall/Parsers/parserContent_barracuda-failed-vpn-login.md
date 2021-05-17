#### Parser Content
```Java
{
Name = barracuda-failed-vpn-login
  Vendor = Barracuda
  Product = Barracuda Firewall
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Session PHS:""", """ authentication failed:""", """Authentication failed""", """ Login """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """Security\s{1,100}({host}[^\s:]{1,2000})\s{1,100}Session""",
    """Authentication failed\s{0,100}\(({src_ip}[A-Fa-f:\d.]{1,2000}?):({src_port}\d{1,100})""",
    """Login\s{1,100}'(({user_email}[^'@\(]{1,2000}@[^'\(@]{1,2000})|({user}[^\s']{1,2000}))'""",
    """Session PHS:\s{0,100}({event_name}[^:=\(]{1,2000}?)\s{0,100}(:|\w+=|\(|$)""",
    """({outcome}failed)"""
  ]
}
```