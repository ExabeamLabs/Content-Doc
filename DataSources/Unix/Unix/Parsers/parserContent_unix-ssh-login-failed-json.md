#### Parser Content
```Java
{
Name = unix-ssh-login-failed-json
  Product = Unix
  DataType = "ssh-login"
  Conditions = [ """"ident":"sshd""", """nvalid user""" ]
  Fields = ${UnixParserTemplates.unix-activity-json.Fields}[
    """(I|i)nvalid user (({domain}[^\\:]+)\\+)?({user}[\w.'\-\\$]+)""",
    """from ({src_ip}[a-fA-F\d.:]+)""",
    """\s{1,100}from\s{1,100}(::[\w]+:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
}
unix-activity-json = {
    Vendor = Unix
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Fields = [
      """"host":"({host}[^"]+)""",
      """"ident":"({event_code}[^"]+)""",
      """"pid":"({pid}\d{1,100})""",
      """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    ]

```