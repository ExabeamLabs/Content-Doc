#### Parser Content
```Java
{
Name = openvpn-app-activity
  Vendor = SSL Open VPN
  Product = SSL Open VPN
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """, mapping:""", """, request size:""" ]
  Fields = [
    """timestamp:\s*\[({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d+ \d\d:\d\d:\d\d ({host}[\w\-.]+)""",
    """Cmd\\*=({activity}[^\s&"]+)""",
    """User\\*=({user}[^\s&%"]+)""",
    """DeviceType\\*=({src_host}[\w\-.]+)""",
    """request size:\s*({bytes}\d+)""",
    """mapping:\s*({app}.+?)\s*,""",
    """ip:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """({additional_info}[^\s,]+?)\s*,\s*status:""",
    """status:\s*({outcome}\d+)""",
  ]
}
```