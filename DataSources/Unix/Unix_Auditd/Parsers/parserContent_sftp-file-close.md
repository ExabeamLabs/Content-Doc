#### Parser Content
```Java
{
Name = sftp-file-close
  DataType = "file-operations"
  Conditions = [ """sftp-server[""",""" close """]
  Fields = ${UnixParserTemplates.sftp-server-activity.Fields}[
    """({activity}close) "+({file_path}({file_parent}[^"]*?[\\\/]+)?\s*({file_name}[^"\\\/]*?(\.({file_ext}\w+))?))"+""",
    """written ({bytes}\d+)"""
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