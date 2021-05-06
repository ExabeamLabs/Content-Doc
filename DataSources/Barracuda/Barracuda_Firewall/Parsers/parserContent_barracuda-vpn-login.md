#### Parser Content
```Java
{
Name = barracuda-vpn-login
  Vendor = Barracuda
  Product = Barracuda Firewall
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """Session PHS:""", """ authentication succeeded:""",  """ Login """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """Info\s+({host}[^\s:]+)\s+Session""",
    """\W(login|user)=(({user_email}[^@\(]+@[^\(@]+)|({user}[^\(]+))\s*\(({src_ip}[A-Fa-f:\d.]+?):({src_port}\d+)""",
    """Login\s+'(({user_email}[^'@\(]+@[^'\(@]+)|({user}[^\s']+))'""", 
    """Session PHS:\s*({event_name}[^:=\(]+?)\s*(:|\w+=|\(|$)""",
    """({outcome}succeeded)"""
  ]
  DupFields = ["user->account"]
}
```