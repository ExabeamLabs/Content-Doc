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
    """@timestamp"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """exabeam_host=({host}[\w\.\-]+)""",
    """\sprincipal name:\s*({user}[^@\.]+)(@({domain}.+?))?\.\s+({failure_reason}[^\.]+)""",
  ]
}
```