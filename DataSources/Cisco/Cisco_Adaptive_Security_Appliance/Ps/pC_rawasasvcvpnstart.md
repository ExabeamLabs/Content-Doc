#### Parser Content
```Java
{
Name = raw-asa-svc-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "vpn-set-ip"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "assigned to session", "-722051" ]
  Fields = [
    """exabeam_host=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Group <({realm}[^<>\s]{1,2000}?)>""",
    """({time}\w+ \d{1,100} (\d\d\d\d )?\d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s{0,100})?({host}[\w.\-]{1,2000})""",
    """[\s\t]{1,2000}\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]{1,2000}) : %ASA""",
    """({host}[^\s]{1,2000})\s{1,20}:\s{1,20}%FTD-""",
    """({time}\d{1,4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}Z?)""",
    """User[\s\t]{1,2000}<(?![^\s]{1,2000}@[^\s]{1,2000})({user}[^>]{1,2000})>[\s\t]{1,2000}IP[\s\t]{1,2000}<({src_ip}[^>]{1,2000})>[\s\t]{1,2000}(?:IPv4[\s\t])?Address[\s\t]{1,2000}<({src_translated_ip}[^>]{1,2000})>"""
    """User[\s\t]{1,2000}<({user_email}[^>@]{1,2000}@[^>@]{1,2000})>[\s\t]{1,2000}IP[\s\t]{1,2000}<({src_ip}[^>]{1,2000})>[\s\t]{1,2000}(?:IPv4[\s\t])?Address[\s\t]{1,2000}<({src_translated_ip}[^>]{1,2000})>"""
  ]


}
```