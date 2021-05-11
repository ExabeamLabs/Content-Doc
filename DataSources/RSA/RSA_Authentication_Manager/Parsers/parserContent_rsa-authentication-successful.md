#### Parser Content
```Java
{
Name = rsa-authentication-successful
  Vendor = RSA
  Product = RSA Authentication Manager
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss:SSS zzz"
  Conditions = [ """,Authentication Success,Valid User,""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d-\d\d-\d\d\s{1,100}\d\d:\d\d:\d\d:\d{1,100}\s{1,100}\w+)""",
    """\s\d\d:\d\d:\d\d:\d{1,100}[^,]+\,([^,]*\,){3}(\s{0,100}|({user}[^,\s]+))\,([^,]*\,){6}(\s{0,100}|({src_ip}[A-Fa-f:\d.]+))\,(\s{0,100}|({src_port}\d{1,100}))\,(\s{0,100}|({dest_ip}[A-Fa-f:\d.]+))\,""",
    """({event_name}Authentication Success)""",
    """({outcome}Success)"""
  ]
}
```