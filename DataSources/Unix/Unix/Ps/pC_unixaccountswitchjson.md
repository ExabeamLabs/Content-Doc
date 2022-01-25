#### Parser Content
```Java
{
Name = unix-account-switch-json
  Product = Unix
  DataType = "unix-account-switch"
  Conditions = [ """"ident":"sudo""", """pam_unix(sudo:session): session""" ]
  Fields = ${UnixParserTemplates.unix-activity-json.Fields}[
    """session (opened|closed) for user ({account}[^\s"]{1,2000})""",
    """\(uid=({user_id}\d{1,100})\)"""
  ]
  DupFields = [ "host->dest_host" ]

unix-activity-json = {
    Vendor = Unix
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Fields = [
      """"host":"({host}[^"]{1,2000})""",
      """"ident":"({event_code}[^"]{1,2000})""",
      """"pid":"({pid}\d{1,100})""",
      """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    
}
```