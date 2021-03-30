#### Parser Content
```Java
{
Name = json-unix-ssh-login-failed
  Product = Unix
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"ident":"sshd""", """error: connect_to""", """failed""" ]
  Fields = ${UnixParserTemplates.unix-activity-json.Fields}[
    """"timestamp":"({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)""",
    """error: connect_to\s+(({dest_ip}\d+.\d+.\d+.\d+)|({dest_host}\S+))\s+port\s+({dest_port}\d+):""",
    """({outcome}failed)"""

  ]
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