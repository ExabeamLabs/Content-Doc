#### Parser Content
```Java
{
Name = citrix-device-aaa-user-failed
  Vendor = Netscaler VPN
  Product = Netscaler VPN
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss"
  Conditions = [ """ AAA Message """, """Failed policy for user""" ]
  Fields = [
    """({time}\d+\/\d+\/\d+:\d+:\d+:\d+)\s*GMT""",
    """GMT\s*({host}[^:]+)\s:\s*({event_code}(\w+\s+){3})[^:]+:\s*"*({failure_reason}.+)for\s*user\s*({user}[^\s]+)""",
    """GMT\s*({host}[^:]+)\s:\s*({event_code}(\w+\s+){2}\w+)\s+[^:]+:\s*"*({failure_reason}.+)\s+for\s*user\s*({user}[^\s]+)"""
  ]
}
```