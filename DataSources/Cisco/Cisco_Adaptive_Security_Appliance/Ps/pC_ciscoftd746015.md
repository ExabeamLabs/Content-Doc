#### Parser Content
```Java
{
Name = cisco-ftd-746015
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "dns-response"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """%FTD-""", """-746015""", """ resolved""" ]
  Fields = [
    """({time}\w+\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)\s({host}[\w\-.]{1,2000})\s:\s{0,100}%FTD-""",
    """%FTD-({priority}\d)-({event_code}[^:]{1,2000})""",
    """\]\s({response}({query}\S+)\s({dns_response_code}resolved)[^=]{1,2000}?)\s{0,100}$"""
  ]


}
```