#### Parser Content
```Java
{
Name = f5-ssh-login-successful
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """pam_audit""", """ tty=""", """attempts=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s({host}\S{1,1000})\sinfo""",
    """start="\w+\s({time_started}\w+\s{0,100}\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """end="\w+\s({time_ended}\w+\s{0,100}\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """host=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\sattempts=""",
    """(?:u|U)ser=({user}[^\s\(]{1,2000})""",
    """\s({protocol}\w+)\(pam_audit\)\[""",
  ]


}
```