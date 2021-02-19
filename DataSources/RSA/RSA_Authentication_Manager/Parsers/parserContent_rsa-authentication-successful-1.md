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
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d-\d\d-\d\d\s+\d\d:\d\d:\d\d:\d+\s+\w+)""",
    """\s\d\d:\d\d:\d\d:\d+[^,]+\,([^,]*\,){3}(\s*|({user}[^,\s]+))\,([^,]*\,){6}(\s*|({src_ip}[A-Fa-f:\d.]+))\,(\s*|({src_port}\d+))\,(\s*|({dest_ip}[A-Fa-f:\d.]+))\,""",
    """({event_name}Authorization Success)""",
    """({outcome}Success)"""
  ]
}
```