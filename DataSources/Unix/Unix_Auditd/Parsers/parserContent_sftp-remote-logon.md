#### Parser Content
```Java
{
Name = sftp-remote-logon
  DataType = "remote-logon"
  Conditions = [ """sftp-server[""",""" session opened """]
  Fields = ${UnixParserTemplates.sftp-server-activity.Fields}[
    """user\s({user}.+?)\sfrom\s\[({src_ip}[A-Fa-f:\d.]+)\]""",
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
        """\d\d:\d\d:\d\d ({host}[^\s]+) sftp-server\[""",
    ]

```