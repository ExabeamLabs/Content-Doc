#### Parser Content
```Java
{
Name = kemp-lb-remote-login
  Vendor = Kemp
  Product = Load Balancer
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """logger: User""", """ Logged in """, """(Session: """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """User\s{1,100}({user}.+?)\s{1,100}\(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)""",
    """({event_name}Logged in)""",
    """({log_type}logger)"""
  ]
}
```