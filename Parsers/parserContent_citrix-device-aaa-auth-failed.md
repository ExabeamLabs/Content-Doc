#### Parser Content
```Java
{
Name = citrix-device-aaa-auth-failed
  Vendor = Netscaler VPN
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss"
  Conditions = [ """ AAA Message """, """Authentication failed""" ]
  Fields = [
    """({time}\d+\/\d+\/\d+:\d+:\d+:\d+)\s*GMT""",
    """GMT\s*({host}[^:]+)\s:\s*({event_code}(\w+\s+){3})[^:]+:\s*"+({failure_reason}.+)\s*for user\s*({user}[^\s]+)"""
  ]
}
```