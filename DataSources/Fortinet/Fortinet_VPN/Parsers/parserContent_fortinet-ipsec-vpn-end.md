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
    """devname="{0,20}({host}[^\s"]{1,2000})""",
    """\d\s({host}[^\s]{1,2000})\sdate=""",
    """rem_?ip=(?:N\/A|({src_ip}[^\s,]{1,2000}))[\s,]""",
    """xauth_?user="(?:N\/A|({user}[^"]{1,2000}))""""
  ]
}
```