#### Parser Content
```Java
{
Name = secure-envoy-failed
  Vendor = Secure Envoy
  Product = Secure Envoy
  Lms = Direct
  DataType = ""authentication-failed""
  TimeFormat = "dd MM yyyy HH:mm:ss"
  Conditions = [ """TORVMVERIFY""","""Access Denied""" ]
  Fields = [
    """({time}\d{1,100}\s\w+\s\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100})\s{0,100}""",
    """TORVMVERIFY01\s({server_name}[^\s]{1,2000})\sUserID=(({user}[^\s@]{1,2000}?)@({domain}[^\s]{1,2000})|({=user}[^\s]{1,2000}))\sAccess\s({auth_method}Denied)\s({failure_reason}.+)ClientIP=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\sRemoteID=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
  ]
}
```