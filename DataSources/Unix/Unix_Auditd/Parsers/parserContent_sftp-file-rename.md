#### Parser Content
```Java
{
Name = sftp-file-rename
   DataType = "file-operations"
   Conditions = [ """sftp-server[""",""" rename """]
   Fields = ${UnixParserTemplates.sftp-server-activity.Fields}[
     """({activity}rename)""",
      """old "{1,20}({src_file_dir}(\/[^\/]{1,2000})*\/)?({src_file_name}[^\/"]{1,2000})"{1,20}\snew\s"{1,20}({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?\s{0,100}({file_name}[^"\\\/]{0,2000}?(\.({file_ext}\w+))?))"{1,20}""",
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