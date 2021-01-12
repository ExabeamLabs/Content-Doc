#### Parser Content
```Java
{
Name = cisco-ftd-113004
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """-113004""", """%FTD-""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s({host}[^\s]+)""",
    """%FTD-({priority}\d+)-({event_code}\d+)""",
    """server\s*=\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """-113004:\s*({event_name}AAA user authentication Successful)"""
    """user\s*=\s*(({user_email}[^@]+@[^\s]+)|({user}[^\s]+))"""
  ]
}
```