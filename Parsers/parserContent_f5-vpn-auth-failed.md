#### Parser Content
```Java
{
Name = f5-vpn-auth-failed
  Vendor = F5 Networks
  Product = Big-IP
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """01490212:4""" ]
  Fields = [
    """@timestamp"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """exabeam_host=({host}[\w\.\-]+)""",
    """authenticate with '({user}[^']+)' failed""",
  ]
}
```