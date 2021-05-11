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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\+\-]\d{1,100}:\d{1,100})\s{1,100}({host}[\w\-.]+)""",
    """\d\d:\d\d:\d\d\s({host}[^\s]+)""",
    """\sAuthentication\s{0,100}<({outcome}[^\s>]+)>""",
    """\sAuthentication\s{0,100}<({outcome}[^\s>]+)\s{1,100}({auth_method}[^>]+)>""",
    """\suser:\s{0,100}<({user}[^\s\>]+)>""",
    """\saccount:\s{0,100}<(({domain}[^\\\s>]+)\\+)?({account}[^\\\s>]+)>""",
    """\sservice:\s{0,100}<({event_code}[^>]+)>""",
    """Caused by:\s{0,100}({failure_reason}[^\s\(:>]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```