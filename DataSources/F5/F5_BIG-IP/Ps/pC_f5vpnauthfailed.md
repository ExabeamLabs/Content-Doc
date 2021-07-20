#### Parser Content
```Java
{
Name = f5-vpn-auth-failed
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """01490212:4""" ]
  Fields = [
    """@timestamp"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """exabeam_host=({host}[\w\.\-]{1,2000})""",
    """authenticate with '({user}[^']{1,2000})' failed""",
  ]
}
```