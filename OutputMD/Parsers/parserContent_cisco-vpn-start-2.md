#### Parser Content
```Java
{
Name = cisco-vpn-start-2
  Vendor = Cisco
  Product = AnyConnect
  Lms = Splunk
  DataType = "vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Client Type: Cisco AnyConnect VPN Agent""", "-722055", "%FTD-"]
  Fields = [
    """exabeam_host=(.+?@\s*)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]+))""",
    """%FTD-({priority}\d+)-({event_code}\d+)""",
    """({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d)""",
    """User\s+<(?![^\s]+@[^\s]+)({user}[^@>]+)(?:@[^>]+)?>""",
    """User\s+<({user_email}[^@>]+@[^@>]+)>""",
    """ IP <({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>""",
    """ Group\s+<({realm}.+?)>""",
  ]
  DupFields = [ "dest_host->host" ]
}
```