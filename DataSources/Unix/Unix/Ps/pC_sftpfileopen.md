#### Parser Content
```Java
{
Name = sftp-file-open
  DataType = "file-operations"
  Conditions = [ """sftp-server[""",""" open """]
  Fields = ${UnixParserTemplates.sftp-server-activity.Fields}[
    """({activity}open) "{1,20}({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?\s{0,100}({file_name}[^"\\\/]{0,2000}?(\.({file_ext}\w+))?))"{1,20}""",
    """flags ({accesses}.+?) mode"""
	]
  
sftp-server-activity = {
    Vendor = Unix
    Product = Unix
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
        """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
        """\d\d:\d\d:\d\d ({host}[^\s]{1,2000}) sftp-server\[""",
    ]
        DupFields = ["host->dest_host"
}
```