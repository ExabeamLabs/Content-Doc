#### Parser Content
```Java
{
Name = sftp-file-rename
   DataType = "file-operations"
   Conditions = [ """sftp-server[""",""" rename """]
   Fields = ${UnixParserTemplates.sftp-server-activity.Fields}[
     """({activity}rename)""",
      """old "+({src_file_dir}(\/[^\/]+)*\/)?({src_file_name}[^\/"]+)"+\snew\s"+({file_path}({file_parent}[^"]*?[\\\/]+)?\s*({file_name}[^"\\\/]*?(\.({file_ext}\w+))?))"+""",
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