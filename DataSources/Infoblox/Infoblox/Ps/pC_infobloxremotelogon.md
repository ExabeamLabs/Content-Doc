#### Parser Content
```Java
{
Name = infoblox-remote-logon
  Vendor = Infoblox
  Product = Infoblox
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
  Conditions = [ """[INFOBLOX]""", """Login_Allowed""", """ip=""", """group=""" ]
  Fields = [
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}\S+\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\S+\s{1,100}({time}\d{1,100}-\d{1,100}-\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)\s{1,100}\[({user}[^\s\]]{1,2000})\]:\s{0,100}({event_code}Login_Allowed)""",
    """ip=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """group=({group}.+?)\s{1,100}(\w+=|$)""",
  ]


}
```