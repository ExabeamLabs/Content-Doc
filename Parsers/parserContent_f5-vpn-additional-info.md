#### Parser Content
```Java
{
Name = f5-vpn-additional-info
  Vendor = F5 Networks
  Product = Big-IP
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """01490005:5:""" ]
  Fields = [
    """\s+01490005:5:\s+({session_id}[^:]+):\s*({additional_info}.+?)\s*$""",
    """\s+01490005:5:.*?({session_id}[^\s:]+):\s+({additional_info}.+?)\s*$"""
  ]
}
```