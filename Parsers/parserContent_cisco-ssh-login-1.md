#### Parser Content
```Java
{
Name = cisco-ssh-login-1
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "HH:mm:ss Z EEE MMM dd yyyy"
  Conditions = [ """-LOGIN_SUCCESS:""" ]
  Fields = [
    """at ({time}\d\d:\d\d:\d\d \w+ \w+ \w+ \d\d \d\d\d\d)""",
    """<\d+>[^:\s]+:\s+({host}[^:\s]+):""",
    """dvc=({host}[^\s]+)""",
    """\[user:\s*({user}[^\]]+)""",
    """\[Source:\s*({src_ip}[^\]]+)""",
    """\[localport:\s*({src_port}[^\]]+)""",
    """({event_code}\S+\d+-LOGIN_SUCCESS)""",
  ]
}
```