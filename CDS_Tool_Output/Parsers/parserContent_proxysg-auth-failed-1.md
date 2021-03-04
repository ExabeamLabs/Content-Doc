#### Parser Content
```Java
{
Name = proxysg-auth-failed-1
  Vendor = ProxySG
  Product = ProxySG
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ProxySG:""", """LDAP: invalid credentials:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """reason:\s*'({failure_reason}[^']+)""",
    """dn:\s*'CN=({user_fullname}[^=]+?),\s*({user_ou}OU=[^\s']+)""",
    """realm:\s*'({realm}[^']+)""",
  ]
}
```