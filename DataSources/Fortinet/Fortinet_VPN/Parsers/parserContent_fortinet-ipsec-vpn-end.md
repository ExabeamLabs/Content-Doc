#### Parser Content
```Java
{
Name = fortinet-ipsec-vpn-end
  Vendor = Fortinet
  Product = Fortinet VPN
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "IPsec connection status change", "tunnel-down", "user=" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """devname="*({host}[^\s"]+)""",
    """\d\s({host}[^\s]+)\sdate=""",
    """rem_?ip=(?:N\/A|({src_ip}[^\s,]+))[\s,]""",
    """xauth_?user="(?:N\/A|({user}[^"]+))""""
  ]
}
```