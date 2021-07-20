#### Parser Content
```Java
{
Name = rsa-authentication-successful-1
  Vendor = RSA
  Product = RSA Authentication Manager
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss:SSS zzz"
  Conditions = [ """,Authorization Success,""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\d\s{1,100}\d\d:\d\d:\d\d:\d{1,100}\s{1,100}\w+)""",
    """\s\d\d:\d\d:\d\d:\d{1,100}[^,]{1,2000}\,([^,]{0,2000}\,){3}(\s{0,100}|({user}[^,\s]{1,2000}))\,([^,]{0,2000}\,){6}(\s{0,100}|({src_ip}[A-Fa-f:\d.]{1,2000}))\,(\s{0,100}|({src_port}\d{1,100}))\,(\s{0,100}|({dest_ip}[A-Fa-f:\d.]{1,2000}))\,""",
    """({event_name}Authorization Success)""",
    """({outcome}Success)"""
  ]
}
```