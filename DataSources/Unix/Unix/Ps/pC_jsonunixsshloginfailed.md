#### Parser Content
```Java
{
Name = json-unix-ssh-login-failed
  Product = Unix
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"ident":"sshd""", """error: connect_to""", """failed""" ]
  Fields = ${UnixParserTemplates.unix-activity-json.Fields}[
    """"timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)""",
    """error: connect_to\s{1,100}(({dest_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})|({dest_host}\S+))\s{1,100}port\s{1,100}({dest_port}\d{1,100}):""",
    """({outcome}failed)"""

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