#### Parser Content
```Java
{
Name = f5-vpn-password-change-failed
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Direct
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"VPN"""", """Password change rejected""" ]
  Fields = [
    """({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}(\+|-)\d{2}:\d{2})\s({host}[\w.-]{1,2000})""",
    """change password for '({target_user}[^']{1,2000})' failed""",
    """({event_name}Password change rejected)"""
  ]


}
```