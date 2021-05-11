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
    """timestamp:\s{0,100}\[({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d{1,100} \d\d:\d\d:\d\d ({host}[\w\-.]+)""",
    """Cmd\\*=({activity}[^\s&"]+)""",
    """User\\*=({user}[^\s&%"]+)""",
    """DeviceType\\*=({src_host}[\w\-.]+)""",
    """request size:\s{0,100}({bytes}\d{1,100})""",
    """mapping:\s{0,100}({app}.+?)\s{0,100}
```