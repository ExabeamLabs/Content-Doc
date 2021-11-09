#### Parser Content
```Java
{
Name = mcafee-nsm-app-login-failed
  DataType = "failed-app-login"
  Conditions = [ """Network Security Manager Login; failed;""", """; User;""" ]
}
mcafee-nsm-app-events = {
    Vendor = McAfee
    Product = McAfee NSM
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ss z"
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d\s\w+);""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """({app}Network Security Manager)""",
      """User\s{1,100}"{1,20}(Administrator|({user_fullname}[^"]{1,2000}))""",
      """;\s{1,100}({user}\w+); User;""",
      """login\s(ID|id|Id)\s{1,100}"{1,20}({user}[^"]{1,2000})""",
      """from\s{1,100}"{1,20}({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """protocol\s{1,100}:\s{1,100}(null|({protocol}[^.\/;]{1,2000}))""",
      """Login URI:\s{0,100}(null|({uri_path}.+?))\s{0,100},\s{0,100}URI""",
      """({outcome}succeeded|failed);""",
      """({event_name}Network Security Manager Login; (succeeded|failed));""",
    ]}
```