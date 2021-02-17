#### Parser Content
```Java
{
Name = avaya-switch-auth-successful
    Vendor = Avaya
  Product = Avaya Ethernet Routing Switch
    Lms = Direct
    DataType = "authentication-successful"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """Session opened""", """ :#6""", """from IP address:""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({event_name}Session opened)""",
      """IP address:\s+({src_ip}[a-fA-F\d.:]+)""",
    ]
  }
```