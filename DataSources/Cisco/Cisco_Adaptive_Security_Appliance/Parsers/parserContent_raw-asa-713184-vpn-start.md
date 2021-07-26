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
    """exabeam_raw=.*?({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
    """({time}\w+ \d{1,100} \d{4} \d\d:\d\d:\d\d)""",
    """%ASA-({priority}\d{1,100})-({event_code}\d{1,100})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """Username = ({user}[^,@]{1,2000}).+?IP = ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\s{1,100}Client Type:\s{1,100}({client_system}.+?)\s{1,100}Client Application Version:\s{1,100}({client_system_version}.+?)\s{1,100}$"""
  ]
}
```