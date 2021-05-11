#### Parser Content
```Java
{
Name = unix-auth-event-1
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ sshd[""", """]: AD authentication succeeded for user""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """AD authentication ({outcome}succeeded) for user ({user}[^""]+)"""
  ]
}
```