#### Parser Content
```Java
{
Name = avaya-switch-auth-failed
    Vendor = Avaya
  Product = Avaya Ethernet Routing Switch
    Lms = Direct
    DataType = "authentication-failed"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """Failed login""", """ :#6""", """IP address:""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({event_name}Failed login)""",
      """IP address:\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    ]
  }
```