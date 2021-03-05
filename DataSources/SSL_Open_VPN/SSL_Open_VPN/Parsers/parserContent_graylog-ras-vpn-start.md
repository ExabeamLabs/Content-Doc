#### Parser Content
```Java
{
Name = graylog-ras-vpn-start
  Vendor = SSL Open VPN
  Product = SSL Open VPN
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ openvpn[""", """MULTI_sva: pool returned """, """IPv4=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """ openvpn\[\d+\]:\s*({user}[^\s\/]+)\/({src_ip}[A-Fa-f:\d.]+):({src_port}\d+)""",
    """IPv4=({src_translated_ip}[A-Fa-f:\d.]+)""",
    """hostname":"({host}[^"]+)""", 
  ]
  DupFields = ["user->account"]
}
```