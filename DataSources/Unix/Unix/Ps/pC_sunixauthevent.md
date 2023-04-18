#### Parser Content
```Java
{
Name = s-unix-auth-event
  Vendor = Unix
  Product = Unix
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """: Authentication <""", """> user: <""", """> account: <""", """> service: <""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\+\-]\d{1,100}:\d{1,100})\s{1,100}""",
    """\d\d:\d\d:\d\d(\.\S+)?\s(::ffff:)?({host}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """({host}({dest_host}[\w\-\.]+))\ssu\[\d+\]:""",
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\+\d\d:\d\d)\s({host}({dest_host}[\w\-\.]+))\s\w+\_\w+:""", 
    """\sAuthentication\s{0,100}<({outcome}[^\s>]{1,2000})>""",
    """\sAuthentication\s{0,100}<({outcome}[^\s>]{1,2000})\s{1,100}({auth_method}[^>]{1,2000})>""",
    """\suser:\s{0,100}<({user}[^\s\>]{1,2000})>""",
    """\saccount:\s{0,100}<(({domain}[^\\\s>]{1,2000})\\+)?({account}[^\\\s>]{1,2000})>""",
    """\sservice:\s{0,100}<({event_code}[^>]{1,2000})>""",
    """Caused by:\s{0,100}({failure_reason}[^\s\(:>]{1,2000})"""
  ]


}
```