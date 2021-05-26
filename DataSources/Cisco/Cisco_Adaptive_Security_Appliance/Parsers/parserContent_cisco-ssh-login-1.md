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
    """<\d{1,100}>[^:\s]{1,2000}:\s{1,100}({host}[^:\s]{1,2000}):""",
    """dvc=({host}[^\s]{1,2000})""",
    """\[user:\s{0,100}({user}[^\]]{1,2000})""",
    """\[Source:\s{0,100}({src_ip}[^\]]{1,2000})""",
    """\[localport:\s{0,100}({src_port}[^\]]{1,2000})""",
    """({event_code}\S+\d{1,100}-LOGIN_SUCCESS)""",
  ]
}
```