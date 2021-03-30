#### Parser Content
```Java
{
Name = s-common-ftp-upload
  Vendor = FTP
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]created /""", """ - 200 """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]+)\s+(\S+\s+){2}\[\d+\]""",
    """({src_ip}\S+)\s+(\S+\s+){2}\[\d+\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s+\[\d+\]""",
    """\]created\s+(-|({file_name}\S+))\s""",
    """\]created\s+(-|({file_path}({file_parent}\/(\S+\/)?)({file_name}\S+)))\s""",
    """\]created\s+\/\S+\.({file_ext}[^\/\.\s]+)\s""",
    """\]created\s+(\S+\s+){2}({outcome}\d+)""",
    """\]created\s+(\S+\s+){4}({bytes}\d+)""",
  ]
  DupFields = [ "host->dest_host", "file_ext->host_file_ext" ]
}
```