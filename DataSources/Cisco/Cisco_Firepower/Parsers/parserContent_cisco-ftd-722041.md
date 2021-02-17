#### Parser Content
```Java
{
Name = cisco-ftd-722041
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """-722041""", """%FTD-""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s({host}[^\s]+)""",
    """%FTD-({priority}\d+)-({event_code}\d+)""",
    """User\s*<({user}[^@>\\]+)(?:@({domain}[^>]+))?>""",
    """\sIP\s+<({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>""",
    """ Group\s+<({group}.+?)>"""
  ]
}
```