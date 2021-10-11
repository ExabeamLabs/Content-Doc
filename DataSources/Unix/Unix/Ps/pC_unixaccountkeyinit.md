#### Parser Content
```Java
{
Name = unix-account-keyinit
  Product = Unix
  DataType = "unix-account-switch"
  Conditions = [ """[][][""", """ pam_keyinit(sudo""" ]
  Fields = ${UnixParserTemplates.unix-events.Fields}[
    """\sUser unknown:\s{0,100}(({domain}[^\\]{1,2000}?)\\+)?({user}[^\\]{1,2000})\s{0,100}$""",
    """pam_keyinit\S*?:\s{0,100}({event_name}.*?change UID to ({account_used_id}\d{1,100}).*?)\s{0,100}$"""
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