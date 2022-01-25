#### Parser Content
```Java
{
Name = cisco-asa-authentication-successful
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Syslog
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """%AAA-5-AAA_AUTH_ADMIN_USER""", """Authentication succeeded for admin user""", """aaa.c:3083""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?(::ffff:)?({host}[\w.-]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({additional_info}Authentication succeeded for admin user) '({user}[^']{1,2000})' on ({dest_ip}[a-fA-F\d:.]{1,2000})""",
    """%AAA-({priority}5)-({event_name}AAA_AUTH_ADMIN_USER)""",
    """aaa.c:({event_code}3083)"""
  ]


}
```