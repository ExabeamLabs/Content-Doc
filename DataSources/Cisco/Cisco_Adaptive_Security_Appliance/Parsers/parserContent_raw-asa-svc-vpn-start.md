#### Parser Content
```Java
{
Name = raw-asa-svc-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "assigned to session", "-722051" ]
  Fields = [
    """exabeam_host=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Group <({realm}[^<>\s]+?)>""",
    """({time}\w+ \d+ (\d\d\d\d )?\d+:\d+:\d+)""",
    """exabeam_source=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s*)?({host}[\w.\-]+)""",
    """[\s\t]+\d\d:\d\d:\d\d\s+({host}[\w.\-]+) : %ASA""",
    """User[\s\t]+<(?![^\s]+@[^\s]+)({user}[^>]+)>[\s\t]+IP[\s\t]+<({src_ip}[^>]+)>[\s\t]+(?:IPv4[\s\t])?Address[\s\t]+<({src_translated_ip}[^>]+)>"""
    """User[\s\t]+<({user_email}[^>@]+@[^>@]+)>[\s\t]+IP[\s\t]+<({src_ip}[^>]+)>[\s\t]+(?:IPv4[\s\t])?Address[\s\t]+<({src_translated_ip}[^>]+)>"""
  ]
}
```