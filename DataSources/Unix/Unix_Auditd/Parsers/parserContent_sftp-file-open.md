#### Parser Content
```Java
{
Name = sftp-file-open
  DataType = "file-operations"
  Conditions = [ """sftp-server[""",""" open """]
  Fields = ${UnixParserTemplates.sftp-server-activity.Fields}[
    """({activity}open) "{1,20}({file_path}({file_parent}[^"]*?[\\\/]+)?\s{0,100}({file_name}[^"\\\/]*?(\.({file_ext}\w+))?))"{1,20}""",
    """flags ({accesses}.+?) mode"""
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