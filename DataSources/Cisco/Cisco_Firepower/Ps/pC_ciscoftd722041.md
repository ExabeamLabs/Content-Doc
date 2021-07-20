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
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s({host}[^\s]{1,2000})""",
    """%FTD-({priority}\d{1,100})-({event_code}\d{1,100})""",
    """User\s{0,100}<({user}[^@>\\]{1,2000})(?:@({domain}[^>]{1,2000}))?>""",
    """\sIP\s{1,100}<({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>""",
    """ Group\s{1,100}<({group}.+?)>"""
  ]
}
```