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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """Security\s{1,100}({host}[^\s:]+)\s{1,100}Session""",
    """Authentication failed\s{0,100}\(({src_ip}[A-Fa-f:\d.]+?):({src_port}\d{1,100})""",
    """Login\s{1,100}'(({user_email}[^'@\(]+@[^'\(@]+)|({user}[^\s']+))'""",
    """Session PHS:\s{0,100}({event_name}[^:=\(]+?)\s{0,100}(:|\w+=|\(|$)""",
    """({outcome}failed)"""
  ]
}
```