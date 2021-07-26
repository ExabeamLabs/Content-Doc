#### Parser Content
```Java
{
Name = unix-ssh-login-failed-json-1
  Product = Unix
  DataType = "ssh-login"
  Conditions = [ """"ident":"sshd""", """fatal: Unable to negotiate""" ]
  Fields = ${UnixParserTemplates.unix-activity-json.Fields}[
    """Unable to negotiate with ({src_ip}[a-fA-F\d.:]{1,2000})""",
  ]
}
unix-activity-json = {
    Vendor = Unix
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Fields = [
      """"host":"({host}[^"]{1,2000})""",
      """"ident":"({event_code}[^"]{1,2000})""",
      """"pid":"({pid}\d{1,100})""",
      """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    ]

```