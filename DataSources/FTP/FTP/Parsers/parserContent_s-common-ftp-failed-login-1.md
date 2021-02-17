#### Parser Content
```Java
{
Name = s-common-ftp-failed-login-1
  Vendor = FTP
  Product = FTP
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]pass ******""", """ - 530 - - - """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]+)\s+(\S+\s+){2}\[\d+\]""",
    """({src_ip}\S+)\s+(\S+\s+){2}\[\d+\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s+\[\d+\]""",
    """\]pass\s+(\S+\s+){2}({outcome}\d+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```