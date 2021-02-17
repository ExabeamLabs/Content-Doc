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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}[^\s]+)\s+\d+\s+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """User\s+((({domain}[^\\\s@]+)\\+)?({user}[^\s\\@]+)).+?\s*logged""",
    """\[({event_name}User.+?logged (out|in))""",
    """user agent:\s+({user_agent}[^)]+)"""
    """\w+@(127.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))"""
  ]
  DupFields = [ "event_name->activity", "host->dest_host" ]
}
```