#### Parser Content
```Java
{
Name = q-asa-6-113039-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = QRadar
  DataType = "vpn-start"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-113039", "%ASA-" ]
  Fields = [
    """exabeam_host=(.+?@\s*)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]+))""",
    """%ASA-({priority}\d+)-({event_code}\d+)""",
    """({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d)""",
    """User\s+<(?![^\s]+@[^\s]+)({user}[^@>]+)(?:@[^>]+)?>""",
    """User\s+<({user_email}[^@>]+@[^@>]+)>""",
    """ IP <({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>""",
    """ Group\s+<({realm}.+?)>""",
  ]
  DupFields = [ "dest_host->host" ]
}
```