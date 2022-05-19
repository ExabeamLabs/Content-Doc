#### Parser Content
```Java
{
Name = cisco-ftd-716039
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """%FTD-""", """-716039""", """Authentication: rejected""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """%FTD-({priority}\d)-({event_code}\d{1,100})""",
    """User\s<(\*+|({user}[^>]{1,2000}))>""",
    """IP\s<({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})>""",
  ]


}
```