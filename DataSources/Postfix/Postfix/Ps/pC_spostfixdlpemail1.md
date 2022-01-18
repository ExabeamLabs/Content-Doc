#### Parser Content
```Java
{
Name = s-postfix-dlp-email-1
  Vendor = Postfix
  Product = Postfix
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """postfix""", """dsn=2.""", """status=sent""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """({msg_id}[^\s"]{1,2000}): to=<""",
    """\d\d:\d\d:\d\d ({host}\S+) postfix[^:]{1,2000}:""",
    """"host(_name)?":"({host}[^"]{1,2000})""",
    """\Wto=<({recipients}[^\>]{1,2000})""",
    """\Wto=<({recipient}[^\s\>,;]{1,2000})""",
    """\Wto=<[^@>]{1,2000}@({external_domain_recipient}[^\s\>,;]{1,2000})""",
    """\Wrelay=({dest_host}[\w\-.]{1,2000})\[({dest_ip}[a-fA-F:\d.]{1,2000})""",
  ]


}
```