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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """reason:\s{0,100}'({failure_reason}[^']{1,2000})""",
    """dn:\s{0,100}'CN=({user_fullname}[^=]{1,2000}?),\s{0,100}({user_ou}OU=[^\s']{1,2000})""",
    """realm:\s{0,100}'({realm}[^']{1,2000})""",
  ]
}
```