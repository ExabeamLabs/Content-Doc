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
    """Authentication\s*<({outcome}[^\s>]+)\s+({auth_method}[^>]+)>.+?user:\s*<({user}[^\s\>]+)>\s*account:\s*<(({domain}[^\\\s>]+)\\+)?({account}[^\\\s>]+)>\s*service:\s*<({event_code}[^>]+)>""",
  ]
  DupFields = [ "host->dest_host" ]
}
```