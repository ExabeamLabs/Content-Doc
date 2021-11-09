#### Parser Content
```Java
{
Name = common-ftp-failed-app-login
  Product = FTP
  DataType = "failed-app-login"
  Conditions = [ """ ftp-log end=""", """"Login Failure"""" ]
}
common-ftp-activity = {
  Vendor = FTP
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Fields = [
    """\s({host}[^\s]{1,2000})\s{1,100}ftp-log""",
    """ ftp-log end=({time}\d{1,100})\s{1,100}[^,]{0,2000},"({accesses}[^"]{1,2000})","({user}[^"]{1,2000})","({src_host}[^"]{1,2000})","({src_ip}[a-fA-F\d.:]{1,2000})","({dest_ip}[a-fA-F\d.:]{1,2000})","({dest_port}[^"]{1,2000})",[^,]{0,2000}(,"(|({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?\s{0,100}({file_name}[^"\\\/]{0,2000}?(\.({file_ext}\w+))?)))"(,"(|({bytes}[^"]{1,2000}))")?)?""",
  ]
  DupFields = [ "accesses->event_name"]}
```