#### Parser Content
```Java
{
Name = cisco-2960-auth-failed-1
  DataType = "authentication-failed"
  Conditions = [ """%DOT1X-5-FAIL:""", """Authentication failed""" ]

cisco-2960-auth-events = {
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """ for client \(({src_mac_address}[^\)]{1,2000})\) on Interface ({src_interface}\S+) """,
    """%({event_code}\w+\-\d{1,100}\-({outcome}[^:]{1,2000}))""",
    """({event_name}Authentication \w+)""",
  
}
```