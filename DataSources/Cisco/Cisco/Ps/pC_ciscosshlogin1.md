#### Parser Content
```Java
{
Name = cisco-ssh-login-1
  Vendor = Cisco
  Product = Cisco
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "HH:mm:ss Z EEE MMM dd yyyy"
  Conditions = [ """-LOGIN_SUCCESS:""" ]
  Fields = [
    """at ({time}\d\d:\d\d:\d\d \w+ \w+ \w+ \d{1,2} \d\d\d\d)""",
    """\s\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})\s""",
    """<\d{1,100}>[^:\s]{1,2000}:\s{1,100}({host}[^:\s]{1,2000}):""",
    """dvc=({host}[^\s]{1,2000})""",
    """\[user:\s{0,100}(({domain}[^\\\]\s]{1,2000})\\{1,20})?({user}[^\]\s]{1,2000})""",
    """\[Source:\s{0,100}({src_ip}[^\]]{1,2000})""",
    """\[localport:\s{0,100}({src_port}[^\]]{1,2000})""",
    """\s({event_code}\S+\d{1,100}-LOGIN_SUCCESS):""",
  ]


}
```