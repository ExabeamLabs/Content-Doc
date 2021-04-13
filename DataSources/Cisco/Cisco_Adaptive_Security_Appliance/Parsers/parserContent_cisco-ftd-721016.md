#### Parser Content
```Java
{
Name = cisco-ftd-721016
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """%FTD-""", """-721016""", """has been created.""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """%FTD-({priority}\d)-({event_code}\d+)""",
    """user\s(({domain}[^\\]+)\\+)?({user}[^,]+),""",
    """IP\s({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
}
```