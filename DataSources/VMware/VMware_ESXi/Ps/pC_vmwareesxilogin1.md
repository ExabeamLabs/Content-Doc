#### Parser Content
```Java
{
Name = vmware-esxi-login-1
  Vendor = VMware
  Product = VMware ESXi
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [""" logged in """,""" [User ""","""Event [""",""" vpxd """ ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}[^\s]{1,2000})\s{1,100}\d{1,100}\s{1,100}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """User\s{1,100}((({domain}[^\\\s@]{1,2000})\\+)?({user}[^\s\\@]{1,2000})).+?\s{0,100}logged""",
    """\[({event_name}User.+?logged (out|in))""",
    """user agent:\s{1,100}({user_agent}[^)]{1,2000})"""
    """\w+@(127.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))"""
  ]
  DupFields = [ "event_name->activity", "host->dest_host" ]


}
```