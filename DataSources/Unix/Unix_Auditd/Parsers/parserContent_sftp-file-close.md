#### Parser Content
```Java
{
Name = sftp-file-close
  DataType = "file-operations"
  Conditions = [ """sftp-server[""",""" close """]
  Fields = ${UnixParserTemplates.sftp-server-activity.Fields}[
    """({activity}close) "{1,20}({file_path}({file_parent}[^"]*?[\\\/]+)?\s{0,100}({file_name}[^"\\\/]*?(\.({file_ext}\w+))?))"{1,20}""",
    """written ({bytes}\d{1,100})"""
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