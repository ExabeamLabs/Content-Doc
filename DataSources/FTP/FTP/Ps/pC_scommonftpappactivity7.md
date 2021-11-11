#### Parser Content
```Java
{
Name = s-common-ftp-app-activity-7
  Product = FTP
  Conditions = [ """]kick """ ]
}
s-common-ftp-app-activity = {
    Vendor = FTP
    Lms = Splunk
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
      """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
      """({host}[\w\.-]{1,2000})\s{1,100}(\S+\s{1,100}){2}\[\d{1,100}\]""",
      """({src_ip}\S+)\s{1,100}(\S+\s{1,100}){2}\[\d{1,100}\]""",
      """(-|(({domain}\S+)[\/\\])?({user}\S+))\s{1,100}\[\d{1,100}\]""",
      """\[\d{1,100}\]({activity}\w+)\s{1,100}""",
      """\[\d{1,100}\]\w+\s{1,100}({object}\S+)""",
      """\[\d{1,100}\]\w+\s{1,100}(\S+\s{1,100}){2}({outcome}\d{1,100})""",
      """\[\d{1,100}\]\w+\s{1,100}(\S+\s{1,100}){4}({bytes}\d{1,100})"""
    ]
    DupFields = [ "host->dest_host" ]}
```