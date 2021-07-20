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
    """({host}[\w\-.]{1,2000})\s{1,100}httpd:""",
    """\Wuser=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrhost=(|(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]{1,2000})))\s""",
    """pam_(sss|unix)\(httpd:auth\):\s{1,100}authentication\s{1,100}({outcome}success|failure);""",
    """({event_code}httpd)""",
  ]
}
```