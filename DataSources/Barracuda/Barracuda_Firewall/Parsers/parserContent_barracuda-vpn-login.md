#### Parser Content
```Java
{
Name = barracuda-vpn-login
  Vendor = Barracuda
  Product = Barracuda Firewall
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ CP-FW """, """ authentication request""", """ user=""", """ Login """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wuser=({user}[^\s\(]{1,2000})\s{0,100}\(({src_ip}[A-Fa-f:\d.]{1,2000}?):({src_port}\d{1,100})""",
    """Login\s{1,100}'({user}[^\s']{1,2000})""",
  ]
  DupFields = ["user->account"]
}
```