#### Parser Content
```Java
{
Name = proxysg-auth-failed-2
  Vendor = ProxySG
  Product = ProxySG
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ProxySG:""", """Authentication failed from""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """Authentication failed from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}): user '({user}[^\s']{1,2000})""",
    """\(realm ({realm}[^\)]{1,2000})""",
  ]
}
```