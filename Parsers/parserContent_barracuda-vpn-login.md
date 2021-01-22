#### Parser Content
```Java
{
Name = barracuda-vpn-login
  Vendor = Barracuda Firewall
  Product = Barracuda Firewall
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ CP-FW """, """ authentication request""", """ user=""", """ Login """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wuser=({user}[^\s\(]+)\s*\(({src_ip}[A-Fa-f:\d.]+?):({src_port}\d+)""",
    """Login\s+'({user}[^\s']+)""",
  ]
  DupFields = ["user->account"]
}
```