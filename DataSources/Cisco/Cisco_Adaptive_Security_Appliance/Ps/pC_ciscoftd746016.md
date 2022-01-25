#### Parser Content
```Java
{
Name = cisco-ftd-746016
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "dns-response"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """%FTD-""", """-746016""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s({host}[\w\-.]{1,2000})\s""",
    """({time}\w+\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)\s({host}[\w\-.]{1,2000})\s:\s{0,100}%FTD-""",
    """%FTD-({priority}\d)-({event_code}[^:]{1,2000})""",
    """({event_name}DNS lookup) for ({query}\S+)\s({dns_response_code}failed)""",
    """,\s{0,100}reason\s{0,100}:\s{0,100}(UNKNOWN|({reason}[^=]{1,2000}?))\s{0,100}($|")"""
  ]


}
```