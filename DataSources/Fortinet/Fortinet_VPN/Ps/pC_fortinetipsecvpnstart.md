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
    """devname="{0,20}({host}[^\s"]{1,2000})""",
    """\d\s({host}[^\s]{1,2000})\sdate=""",
    """rem_?ip=({src_ip}[^\s,]{1,2000})[\s,]""",
    """tunnel_?ip=(?:N\/A|({src_translated_ip}[^\s,]{1,2000}))[\s,]""",
    """xauth_?user="(?:N\/A|({user}[^"]{1,2000}))""""
    """group="(?:N\/A|({realm}[^"]{1,2000}))""", 
  ]
  DupFields = ["user->account"]
}
```