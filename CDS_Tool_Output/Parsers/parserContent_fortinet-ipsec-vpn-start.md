#### Parser Content
```Java
{
Name = fortinet-ipsec-vpn-start
  Vendor = Fortinet
  Product = Fortinet VPN
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "IPsec connection status change", "tunnel-up", "user=" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """devname="*({host}[^\s"]+)""",
    """\d\s({host}[^\s]+)\sdate=""",
    """rem_?ip=({src_ip}[^\s,]+)[\s,]""",
    """tunnel_?ip=(?:N\/A|({src_translated_ip}[^\s,]+))[\s,]""",
    """xauth_?user="(?:N\/A|({user}[^"]+))""""
  ]
}
```