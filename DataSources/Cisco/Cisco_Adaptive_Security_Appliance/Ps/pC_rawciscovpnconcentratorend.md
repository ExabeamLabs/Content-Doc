#### Parser Content
```Java
{
Name = raw-cisco-vpnconcentrator-end
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ " disconnected:  Session Type: ", "AUTH/28" ]
  Fields = [
    """({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_host=(.+?@\s{0,100})?({host}[\w.\-]{1,2000})""",
    """RPT=\d{1,100}\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """User\s{1,100}\[({user}[^\]]{1,2000})"""
  ]


}
```