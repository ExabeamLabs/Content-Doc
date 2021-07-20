#### Parser Content
```Java
{
Name = f5-ssh-failed-logon
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "failed-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss" 
  Conditions = [ """pam_audit""", """ tty=""", """failed to login""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """start="\w+\s({time_started}\w+\s{0,100}\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """end="\w+\s({time_ended}\w+\s{0,100}\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """host=({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """(?:u|U)ser=({user}[^\s]{1,2000})\s""",
    """\s({protocol}\w+)\(pam_audit\)\[""",
  ]
}
```