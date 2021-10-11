#### Parser Content
```Java
{
Name = sftp-remote-logon
  DataType = "remote-logon"
  Conditions = [ """sftp-server[""",""" session opened """]
  Fields = ${UnixParserTemplates.sftp-server-activity.Fields}[
    """user\s({user}.+?)\sfrom\s\[({src_ip}[A-Fa-f:\d.]{1,2000})\]""",
    """({event_name}session opened)"""
	]
  }
sftp-server-activity = {
    Vendor = Unix
    Product = Unix
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
        """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
        """\d\d:\d\d:\d\d ({host}[^\s]{1,2000}) sftp-server\[""",
    ]

```