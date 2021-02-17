#### Parser Content
```Java
{
Name = raw-cisco-vpnconcentrator-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ " connected, Session Type:", "AUTH/22" ]
  Fields = [
    """({time}\d+\/\d+\/\d+ \d+:\d+:\d+)""",
    """exabeam_host=(.+?@\s*)?({host}[\w.\-]+)""",
    """RPT=\d+\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """User\s+\[({user}[^\]]+)"""
  ]
}
```