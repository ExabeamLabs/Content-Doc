#### Parser Content
```Java
{
Name = f5-vpn-auth-failed-1
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"VPN"""", """SECURID_AUTH_STATE_ACCESS_DENIED""" ]
  Fields = [
    """({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}(\+|-)\d{2}:\d{2})\s({host}[\w.-]{1,2000})""",
    """authentication with '({user}[^']{1,2000})' failed""",
    """Error_Message="({event_name}[^\."]{1,2000})"""
  ]


}
```