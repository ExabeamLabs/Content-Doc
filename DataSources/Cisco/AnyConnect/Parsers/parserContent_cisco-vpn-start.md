#### Parser Content
```Java
{
Name = cisco-vpn-start
  Vendor = Cisco
  Product = AnyConnect
  Lms = Splunk
  DataType = "vpn-login"
  TimeFormat = "yyyy MMM dd HH:mm:ss"
  Conditions = [ """AnyConnect parent session started.""", "-113039", "%FTD-"]
  Fields = [
    """exabeam_host=(.+?@\s*)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]+))""",
    """exabeam_host=(.+?@\s*)?({host}[\w.\-]+)""",
    """({host}[^\s]+)\s{1,20}:\s{1,20}%FTD-""",
    """({time}\d{1,4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}Z?)""",
    """%FTD-({priority}\d+)-({event_code}\d+)""",
    """({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d)""",
   """({time}\d+ \w+ \d+ \d+:\d+:\d+)""",
    """User\s+<(?![^\s]+@[^\s]+)({user}[^@>]+)(?:@[^>]+)?>""",
    """User\s+<({user_email}[^@>]+@[^@>]+)>""",
    """ IP <({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>""",
    """ Group\s+<({realm}.+?)>""",
  ]
}
```