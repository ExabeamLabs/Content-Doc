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
    """\w+\s+\d+\s+\d\d:\d\d:\d\d\s+\S+\s+({host}[\w\-.]+)\s+\S+\s+({time}\d+-\d+-\d+\s+\d+:\d+:\d+\.\d+Z)\s+\[({user}[^\s\]]+)\]:\s*({event_code}Login_Allowed)""",
    """ip=({src_ip}[A-Fa-f:\d.]+)""",
    """group=({group}.+?)\s+(\w+=|$)""",
  ]
}
```