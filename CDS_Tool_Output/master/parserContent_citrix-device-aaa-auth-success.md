#### Parser Content
```Java
{
Name = citrix-device-aaa-auth-success
  Vendor = Netscaler VPN
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss"
  Conditions = [ """ AAA Message """, """Succeeded policy for user""" ]
  Fields = [
    """({time}\d+\/\d+\/\d+:\d+:\d+:\d+)\s*GMT""",
    """GMT\s*({host}[^:\s]+)(\s\S+)?\s:\s*({event_code}(\w+\s+){3})[^:]+:\s*"+({event_name}.+)\s*for user\s*({user}[^\s]+)\s*=\s*({auth_method}[^"]+)"+""",
    """GMT\s*({host}[^:\s]+)(\s\S+)?\s:\s*({event_code}(\w+\s+){2}\w+)\s+[^:]+:\s*"+({event_name}.+)\s+for user\s*({user}[^\s]+)\s*=\s*({auth_method}[^"]+)"+"""
  ]
  DupFields = ["host->src_host"]
}
```