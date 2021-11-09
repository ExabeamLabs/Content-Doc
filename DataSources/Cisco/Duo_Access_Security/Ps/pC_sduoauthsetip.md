#### Parser Content
```Java
{
Name = s-duo-auth-set-ip
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Splunk
  DataType = "authentication-set-ip"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """[DuoForwardServer""","""login attempt for username"""]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\]\s{1,100}\(\(\'({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\]\s{1,100}\(\(\'.+?\',\s{0,100}({session_id}\d{1,100})\)""",
    """login attempt for username.*?\'({user}[^']{1,2000})\'""" ]
}
}
```