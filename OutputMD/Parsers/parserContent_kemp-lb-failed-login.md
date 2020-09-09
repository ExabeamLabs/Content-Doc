#### Parser Content
```Java
{
Name = kemp-lb-failed-login
  Vendor = Kemp
  Product = Load Balancer
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """logger: User""", """ Login failed""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """User\s+({user}.+?)\s+\(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)""",
    """({event_name}Login failed)""",
    """({log_type}logger)""",
    """({failure_reason}Invalid user\/password)""",
  ]
}
```