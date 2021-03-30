#### Parser Content
```Java
{
Name = httpd-auth-event
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """pam_""", """ httpd: """, """(httpd:auth):""", """: authentication""", """tty=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]+)\s+httpd:""",
    """\Wuser=({user}.+?)(\s+\w+=|\s*$)""",
    """\Wrhost=(|(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]+)))\s""",
    """pam_(sss|unix)\(httpd:auth\):\s+authentication\s+({outcome}success|failure);""",
    """({event_code}httpd)""",
  ]
}
```