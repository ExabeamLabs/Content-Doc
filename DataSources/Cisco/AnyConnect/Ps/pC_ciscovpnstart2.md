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
    """exabeam_host=(.+?@\s{0,100})?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]{1,2000}))""",
    """%FTD-({priority}\d{1,100})-({event_code}\d{1,100})""",
    """({host}[^\s]{1,2000})\s{1,20}:\s{1,20}%FTD-""",
    """({time}\w+ \d{1,100} \d{4} \d\d:\d\d:\d\d)""",
    """({time}\d{1,4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}Z?)""",
    """User\s{1,100}<(?![^\s]{1,2000}@[^\s]{1,2000})({user}[^@>]{1,2000})(?:@[^>]{1,2000})?>""",
    """User\s{1,100}<({user_email}[^@>]{1,2000}@[^@>]{1,2000})>""",
    """ IP <({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>""",
    """ Group\s{1,100}<({realm}.+?)>""",
    """Cisco AnyConnect VPN Agent for ({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(X|x)11|(W|w)indows|(L|l)inux|(M|m)acintosh|(D|d)arwin)""", 
  ]
}
```