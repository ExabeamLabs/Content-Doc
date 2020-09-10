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
    """exabeam_host=([^=]+@\s*)?({host}[\w.\-]+)""",
    """({event_code}%SSH-[^:]+)""",
    """SSH2_USERAUTH:\s*User '(|({user}[^']+))' authentication for SSH2 Session from ({src_ip}[A-Fa-f:\d.]+)""",
    """({outcome}Succeeded|Failed)""",
  ]
}
```