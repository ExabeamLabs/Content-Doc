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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """openvpn\[({pid}[^\]]{1,2000})\]""",
    """openvpn\[[^\]]{1,2000}\]\:\s({user}[^\/]{1,2000})\/({src_ip}[a-fA-F\d.:]{1,2000})\:({src_port}\d{1,100})""",
    """({event_name}Inactivity timeout)""",
    """Inactivity timeout\s({additional_info}[^\"]{1,2000}?)\s{0,100}("|$)""",
  ]
}
```