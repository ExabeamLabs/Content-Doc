#### Parser Content
```Java
{
Name = unix-auth-failed-2
  DataType = "authentication-failed"
  Conditions = [ """[][][""", """ pam_unix(sudo""", """ authentication failure""" ]
  Fields = ${UnixParserTemplates.unix-events.Fields}[
    """\sruser=(|({account}.+?))(\s+\w+=|\s*$)""",
    """\suser=(|({user}.+?))(\s+\w+=|\s*$)""",
    """\suid=(|({user_id}.+?))(\s+\w+=|\s*$)""",
  ]
}
unix-events = {
  Vendor = Unix
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """\[({src_ip}[a-fA-F\d.:]+)\]\[\d+\]\[\w+\]\[\]<\d+>\d+ ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d+(\+|\-)\d\d:\d\d ({host}[\w.\-]+) ({event_code}\S+)""",
  ]

```