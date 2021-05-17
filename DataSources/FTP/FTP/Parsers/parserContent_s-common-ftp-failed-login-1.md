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
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]{1,2000})\s{1,100}(\S+\s{1,100}){2}\[\d{1,100}\]""",
    """({src_ip}\S+)\s{1,100}(\S+\s{1,100}){2}\[\d{1,100}\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s{1,100}\[\d{1,100}\]""",
    """\]pass\s{1,100}(\S+\s{1,100}){2}({outcome}\d{1,100})""",
  ]
  DupFields = [ "host->dest_host" ]
}
```