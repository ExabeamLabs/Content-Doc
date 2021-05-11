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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """reason:\s{0,100}'({failure_reason}[^']+)""",
    """dn:\s{0,100}'CN=({user_fullname}[^=]+?),\s{0,100}({user_ou}OU=[^\s']+)""",
    """realm:\s{0,100}'({realm}[^']+)""",
  ]
}
```