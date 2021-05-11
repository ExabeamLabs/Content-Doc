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
    """<\d{1,100}>[^:\s]+:\s{1,100}({host}[^:\s]+):""",
    """dvc=({host}[^\s]+)""",
    """\[user:\s{0,100}({user}[^\]]+)""",
    """\[Source:\s{0,100}({src_ip}[^\]]+)""",
    """\[localport:\s{0,100}({src_port}[^\]]+)""",
    """({event_code}\S+\d{1,100}-LOGIN_SUCCESS)""",
  ]
}
```