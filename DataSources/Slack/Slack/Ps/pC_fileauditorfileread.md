#### Parser Content
```Java
{
Name = fileauditor-file-read
  Conditions = [ """[ FILE_ATTRIBUTES=""", """[ CREATION_TIME=""", """[ MESSAGE=Read ]""" ]
}
fileauditor-file-operations = {
  Vendor = FileAuditor
  Product = FileAuditor
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Fields = [
    """\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}[\+\-]\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})""",
    """\[ CREATION_TIME=({time}\d{10})""",
    """\[ OLD_SHARE_PATH=({src_file_dir}[^\]]{1,2000}\\+)?({src_file_name}[^\]\\\/]{1,2000}?)\s{0,100}\]""",
    """\[ NEW_FILE_NAME=({file_path}({file_parent}[^\]]{0,2000}?)[\\\/]{0,2000}({file_name}[^\\\]]{1,2000}?(\.({file_ext}[^\.\s\]]{1,2000}))?))\s{0,100}\]""",
    """\[ CLIENT_HOST=(-|(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]{1,2000})))""",
    """\[ CLIENT_IP=(::1|({src_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\[ MESSAGE=({accesses}.+?)\s{0,100}\]""",
    """\[ USERNAME=({user}[^\s\]]{1,2000}?)\s{0,100}\]""",
  ]
  DupFields = [ "host->dest_host" ]}
```