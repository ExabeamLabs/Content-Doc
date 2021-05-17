#### Parser Content
```Java
{
Name = unix-auth-failed-2
  Product = Unix
  DataType = "authentication-failed"
  Conditions = [ """[][][""", """ pam_unix(sudo""", """ authentication failure""" ]
  Fields = ${UnixParserTemplates.unix-events.Fields}[
    """\sruser=(|({account}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\suser=(|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\suid=(|({user_id}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
unix-events = {
  Vendor = Unix
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """\[({src_ip}[a-fA-F\d.:]{1,2000})\]\[\d{1,100}\]\[\w+\]\[\]<\d{1,100}>\d{1,100} ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}(\+|\-)\d\d:\d\d ({host}[\w.\-]{1,2000}) ({event_code}\S+)""",
  ]

```