#### Parser Content
```Java
{
Name = f5-vpn-session-data
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-session-data"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """01490521:5:"""  ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[^\s]{1,2000})""",
    """\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s([^\s]{1,2000}\s)?[^\s]{1,2000}\[\d{1,100}\]""",
    """01490521:5:.*?({session_id}[^:\s]{1,2000}): Session statistics""",
    """bytes out:\s{0,100}({bytes_out}\d{1,100})"""
  ]
}
```