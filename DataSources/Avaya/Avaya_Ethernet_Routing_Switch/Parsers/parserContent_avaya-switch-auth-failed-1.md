#### Parser Content
```Java
{
Name = avaya-switch-auth-failed-1
    Vendor = Avaya
  Product = Avaya Ethernet Routing Switch
    Lms = Direct
    DataType = "authentication-failed"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """:Authentication Failure""", """Server IP""", """Intruder IP""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({event_name}Authentication Failure)""",
      """Server IP\s{1,100}({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """Intruder IP\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    ]
  }
```