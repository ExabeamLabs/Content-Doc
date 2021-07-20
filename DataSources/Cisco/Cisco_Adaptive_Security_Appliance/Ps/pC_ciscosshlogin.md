#### Parser Content
```Java
{
Name = cisco-ssh-login
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """%SSH-""", """SSH2_USERAUTH:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w.\-]{1,2000})""",
    """({event_code}%SSH-[^:]{1,2000})""",
    """SSH2_USERAUTH:\s{0,100}User '(|({user}[^']{1,2000}))' authentication for SSH2 Session from ({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """({outcome}Succeeded|Failed)""",
  ]
}
```