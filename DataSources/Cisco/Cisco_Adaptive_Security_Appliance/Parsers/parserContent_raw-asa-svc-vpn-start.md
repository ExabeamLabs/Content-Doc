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
    """Group <({realm}[^<>\s]+?)>""",
    """({time}\w+ \d{1,100} (\d\d\d\d )?\d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s{0,100})?({host}[\w.\-]+)""",
    """[\s\t]+\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]+) : %ASA""",
    """({host}[^\s]+)\s{1,20}:\s{1,20}%FTD-""",
    """({time}\d{1,4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}Z?)""",
    """User[\s\t]+<(?![^\s]+@[^\s]+)({user}[^>]+)>[\s\t]+IP[\s\t]+<({src_ip}[^>]+)>[\s\t]+(?:IPv4[\s\t])?Address[\s\t]+<({src_translated_ip}[^>]+)>"""
    """User[\s\t]+<({user_email}[^>@]+@[^>@]+)>[\s\t]+IP[\s\t]+<({src_ip}[^>]+)>[\s\t]+(?:IPv4[\s\t])?Address[\s\t]+<({src_translated_ip}[^>]+)>"""
  ]
}
```