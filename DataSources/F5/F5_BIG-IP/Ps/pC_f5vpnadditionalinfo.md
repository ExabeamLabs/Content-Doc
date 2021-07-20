#### Parser Content
```Java
{
Name = f5-vpn-additional-info
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """01490005:5:""" ]
  Fields = [
    """\s{1,100}01490005:5:\s{1,100}({session_id}[^:]{1,2000}):\s{0,100}({additional_info}.+?)\s{0,100}$""",
    """\s{1,100}01490005:5:.*?({session_id}[^\s:]{1,2000}):\s{1,100}({additional_info}.+?)\s{0,100}$"""
  ]
}
```