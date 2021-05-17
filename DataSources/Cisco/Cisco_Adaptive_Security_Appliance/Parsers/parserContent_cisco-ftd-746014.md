#### Parser Content
```Java
{
Name = cisco-ftd-746014
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "dns-response"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """%FTD-""", """-746014""", """ address """, """ obsolete""" ]
  Fields = [
    """({time}\w+\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)\s({host}[\w\-.]{1,2000})\s:\s{0,100}%FTD-""",
    """%FTD-({priority}\d)-({event_code}[^:]{1,2000})""",
    """\]\s({response}({query}\S+)[^=]{1,2000}?({dns_response_code}obsolete))"""
  ]
}
```