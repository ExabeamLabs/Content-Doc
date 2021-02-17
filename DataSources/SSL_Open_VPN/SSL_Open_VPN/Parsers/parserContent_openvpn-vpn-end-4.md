#### Parser Content
```Java
{
Name = openvpn-vpn-end-4
  Vendor = SSL Open VPN
  Product = SSL Open VPN
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """openvpn""", """Inactivity timeout""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """openvpn\[[^\]]+\]\:\s({user}[^\/]+)\/({src_ip}[a-fA-F\d.:]+)\:({src_port}\d+)""",
    """\[[^\]]+\]\s({event_name}Inactivity timeout)""",
    """Inactivity timeout\s({additional_info}[^\"]+)\s"""",
  ]
}
```