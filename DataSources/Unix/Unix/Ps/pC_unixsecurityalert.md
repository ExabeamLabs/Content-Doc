#### Parser Content
```Java
{
Name = unix-security-alert
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """POSSIBLE BREAK-IN ATTEMPT!""", """ sshd[""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({alert_name}POSSIBLE BREAK-IN ATTEMPT!)""",
    """ Address ({src_ip}[a-fA-F\d.:]{1,2000}) maps to ({src_host}[^,]{1,2000})""",
    """({host}[\w.\-]{1,2000}) ({process}sshd)\[""",
    """({additional_info}Address .+?- POSSIBLE BREAK-IN ATTEMPT!)\s{0,100}$"""
  ]
  DupFields = [ "alert_name->alert_type" ]


}
```