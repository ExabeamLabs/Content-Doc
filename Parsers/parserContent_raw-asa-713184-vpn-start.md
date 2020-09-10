#### Parser Content
```Java
{
Name = raw-asa-713184-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-713184", "%ASA-" ]
  Fields = [
    """exabeam_raw=.*?({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d)""",
    """%ASA-({priority}\d+)-({event_code}\d+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """Username = ({user}[^,@]+).+?IP = ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\s+Client Type:\s+({client_system}.+?)\s+Client Application Version:\s+({client_system_version}.+?)\s+$"""
  ]
}
```