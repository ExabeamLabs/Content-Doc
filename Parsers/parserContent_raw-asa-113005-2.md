#### Parser Content
```Java
{
Name = raw-asa-113005-2
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """%ASA""" , """-113005""", """ AAA failure ""","""server =""" ]
  Fields = [
    """({time}\w+\s\d+\s\d+\s\d+:\d+:\d+)""",
    """exabeam_host=({host}[^\s]+)""",
    """reason\s*=\s*({failure_reason}.+?)\s*:""",
    """user\s*=\s*(?:|({user}[^:]+))\s+:""",
    """user IP\s*=\s*({src_ip}[a-fA-F\d.:]+)""",
 ]
}
```