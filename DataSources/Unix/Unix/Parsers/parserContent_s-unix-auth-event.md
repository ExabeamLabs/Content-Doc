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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\+\-]\d+:\d+)\s+({host}[\w\-.]+)""",
    """\sAuthentication\s*<({outcome}[^\s>]+)\s+({auth_method}[^>]+)>""",
    """\suser:\s*<({user}[^\s\>]+)>""",
    """\saccount:\s*<(({domain}[^\\\s>]+)\\+)?({account}[^\\\s>]+)>""",
    """\sservice:\s*<({event_code}[^>]+)>""",
  ]
  DupFields = [ "host->dest_host" ]
}
```