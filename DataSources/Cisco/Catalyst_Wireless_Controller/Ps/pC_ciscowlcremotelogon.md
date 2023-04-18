#### Parser Content
```Java
{
Name = cisco-wlc-remote-logon
  Vendor = Cisco
  Product = Catalyst Wireless Controller
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ %WEBSERVER-5-LOGIN_PASSED: """, """ Login Successful """ ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """Login Successful from host ({src_ip}[A-Fa-f\d:.]{1,2000}) by user '(({user_email}[^@]{1,2000}@[^']{1,2000})|({user_id}\d{1,2000})|({user}[^']{1,2000}))'""",
    """%({event_name}WEBSERVER-5-LOGIN_PASSED):"""
  ]


}
```