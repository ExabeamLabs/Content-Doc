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
    """({time}\d+\s\w+\s\d+\s\d+:\d+:\d+)\s*""",
    """TORVMVERIFY01\s({server_name}[^\s]+)\sUserID=(({user}[^\s@]+?)@({domain}[^\s]+)|({=user}[^\s]+))\sAccess\s({auth_method}Denied)\s({failure_reason}.+)ClientIP=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\sRemoteID=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
  ]
}
```