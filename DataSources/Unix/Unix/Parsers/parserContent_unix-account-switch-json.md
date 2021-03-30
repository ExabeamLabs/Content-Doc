#### Parser Content
```Java
{
Name = unix-account-switch-json
  Product = Unix
  DataType = "unix-account-switch"
  Conditions = [ """"ident":"sudo""", """pam_unix(sudo:session): session""" ]
  Fields = ${UnixParserTemplates.unix-activity-json.Fields}[
    """session (opened|closed) for user ({account}[^\s"]+)""",
    """\(uid=({user_id}\d+)\)"""
  ]
  DupFields = [ "host->dest_host" ]
}
unix-activity-json = {
    Vendor = Unix
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Fields = [
      """"host":"({host}[^"]+)""",
      """"ident":"({event_code}[^"]+)""",
      """"pid":"({pid}\d+)""",
      """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    ]

```