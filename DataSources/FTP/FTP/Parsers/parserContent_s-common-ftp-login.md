#### Parser Content
```Java
{
Name = s-common-ftp-login
  Vendor = FTP
  Product = FTP
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]pass ******""", """ - 230 - - - """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s{0,100})?({host}[^\s]+)""",
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """({host}[\w\.-]+)\s{1,100}(\S+\s{1,100}){2}\[\d{1,100}\]""",
    """({src_ip}\S+)\s{1,100}(\S+\s{1,100}){2}\[\d{1,100}\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s{1,100}\[\d{1,100}\]""",
    """\]pass\s{1,100}(\S+\s{1,100}){2}({outcome}\d{1,100})""",
  ]
  DupFields = [ "host->dest_host" ]
}
```