#### Parser Content
```Java
{
Name = code42-file-read
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "file-read"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions= [ """"action": "application-read"""", """"file": {""", """Code42""" ]
  Fields = [
    """timestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)"""",
    """"action":\s{0,100}"({action}application-({accesses}read))"""",
    """"email":\s{0,100}"({user_email}[^"]{1,2000})"""",
    """"file"[^\}]{1,2000}?"name":\s{0,100}"({file_name}[^"]{1,2000})",\s{0,100}"directory":\s{0,100}"({file_parent}[^"]{1,2000})",\s{0,100}"category":\s{0,100}"({file_type}[^"]{1,2000})"""",
    """"owner":\s{0,100}"({user}[^"]{1,2000})"""",
    """"ip":\s{0,100}"({src_ip}[A-Fa-f\d.:]{1,2000})"""",
  ]


}
```