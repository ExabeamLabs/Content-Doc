#### Parser Content
```Java
{
Name = barracuda-failed-vpn-login
  Vendor = Barracuda
  Product = Barracuda Firewall
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ CP-FW """, """ authentication failed:""", """Authentication failed""", """ Login """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """Authentication failed\s*\(({src_ip}[A-Fa-f:\d.]+?):({src_port}\d+)""",
    """Login\s+'({user}[^\s']+)""",
  ]
}
```