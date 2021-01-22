#### Parser Content
```Java
{
Name = f5-ssh-login-successful
  Vendor = F5
  Product = Big-IP
  Lms = Splunk
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """pam_audit""", """ tty=""", """attempts=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """start="\w+\s({time_started}\w+\s*\d+\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """end="\w+\s({time_ended}\w+\s*\d+\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """host=({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """(?:u|U)ser=({user}[^\s]+)\s""",
    """\s({protocol}\w+)\(pam_audit\)\[""",
  ]
}
```