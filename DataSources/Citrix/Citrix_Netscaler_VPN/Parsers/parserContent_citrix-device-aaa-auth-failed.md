#### Parser Content
```Java
{
Name = citrix-device-aaa-auth-failed
  Vendor = Citrix
  Product = Citrix Netscaler VPN
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss"
  Conditions = [ """ AAA Message """, """Authentication failed""" ]
  Fields = [
    """({time}\d{1,100}\/\d{1,100}\/\d{1,100}:\d{1,100}:\d{1,100}:\d{1,100})\s{0,100}GMT""",
    """GMT\s{0,100}({host}[^:]+)\s:\s{0,100}({event_code}(\w+\s{1,100}){3})[^:]+:\s{0,100}"{1,20}({failure_reason}.+)\s{0,100}for user\s{0,100}({user}[^\s]+)"""
  ]
}
```