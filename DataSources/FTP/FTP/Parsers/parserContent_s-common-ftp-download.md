#### Parser Content
```Java
{
Name = s-common-ftp-download
  Vendor = FTP
  Product = FTP
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]sent /""", """ - 200 """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s{0,100})?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]+)\s{1,100}(\S+\s{1,100}){2}\[\d{1,100}\]""",
    """({src_ip}\S+)\s{1,100}(\S+\s{1,100}){2}\[\d{1,100}\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s{1,100}\[\d{1,100}\]""",
    """\]sent\s{1,100}(-|({file_name}\S+))\s""",
    """\]sent\s{1,100}(-|({file_path}({file_parent}\/(\S+\/)?)({file_name}\S+)))\s""",
    """\]sent\s{1,100}\/\S+\.({file_ext}[^\/\.\s]+)\s""",
    """\]sent\s{1,100}(\S+\s{1,100}){2}({outcome}\d{1,100})""",
    """\]sent\s{1,100}(\S+\s{1,100}){3}({bytes}\d{1,100})""",
  ]
  DupFields = [ "host->dest_host", "file_ext->host_file_ext" ]
}
```