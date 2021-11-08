#### Parser Content
```Java
{
Name = f5-vpn-session-end
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """01490""", """:5:""", """Session deleted""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[^\s"]{1,2000})""",
    """\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s([^\s]{1,2000}\s)?[^\s]{1,2000}\[\d{1,100}\]""",
    """"host":\{"name":"({host}[^"]{1,2000})""",
    """hostname="({host}[^"]{1,2000})""",
    """:5:.*?({session_id}[^:\s]{1,2000}): Session deleted"""
  ]
}
```