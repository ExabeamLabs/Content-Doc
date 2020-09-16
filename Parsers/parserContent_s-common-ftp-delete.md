#### Parser Content
```Java
{
Name = s-common-ftp-delete
  Vendor = FTP
  Product = FTP
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]dele """, """ - 250 - - - """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]+)\s+(\S+\s+){2}\[\d+\]""",
    """({src_ip}\S+)\s+(\S+\s+){2}\[\d+\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s+\[\d+\]""",
    """\]dele\s+(-|({file_name}\S+))\s""",
    """\]dele\s+(-|({file_path}({file_parent}\/(\S+\/)?)({file_name}\S+)))\s""",
    """\]dele\s+\/\S+\.({file_ext}[^\/\.\s]+)\s""",
    """\]dele\s+(\S+\s+){2}({outcome}\d+)""",
  ]
  DupFields = [ "host->dest_host", "file_ext->host_file_ext" ]
}
```