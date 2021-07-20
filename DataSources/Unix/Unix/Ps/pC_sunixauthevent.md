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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\+\-]\d{1,100}:\d{1,100})\s{1,100}({host}[\w\-.]{1,2000})""",
    """\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})""",
    """\sAuthentication\s{0,100}<({outcome}[^\s>]{1,2000})>""",
    """\sAuthentication\s{0,100}<({outcome}[^\s>]{1,2000})\s{1,100}({auth_method}[^>]{1,2000})>""",
    """\suser:\s{0,100}<({user}[^\s\>]{1,2000})>""",
    """\saccount:\s{0,100}<(({domain}[^\\\s>]{1,2000})\\+)?({account}[^\\\s>]{1,2000})>""",
    """\sservice:\s{0,100}<({event_code}[^>]{1,2000})>""",
    """Caused by:\s{0,100}({failure_reason}[^\s\(:>]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]
}
```