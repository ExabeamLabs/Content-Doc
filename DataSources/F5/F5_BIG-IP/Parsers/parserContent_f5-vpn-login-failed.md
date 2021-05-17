#### Parser Content
```Java
{
Name = f5-vpn-login-failed
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """01490106:4""" ]
  Fields = [
    """@timestamp"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """exabeam_host=({host}[\w\.\-]{1,2000})""",
    """\sprincipal name:\s{0,100}({user}[^@\.]{1,2000})(@({domain}.+?))?\.\s{1,100}({failure_reason}[^\.]{1,2000})""",
  ]
}
```