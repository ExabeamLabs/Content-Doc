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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """ openvpn\[\d{1,100}\]:\s{0,100}({user}[^\s\/]+)\/({src_ip}[A-Fa-f:\d.]+):({src_port}\d{1,100})""",
    """IPv4=({src_translated_ip}[A-Fa-f:\d.]+)""",
    """hostname":"({host}[^"]+)""", 
  ]
  DupFields = ["user->account"]
}
```