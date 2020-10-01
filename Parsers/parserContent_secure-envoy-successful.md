#### Parser Content
```Java
{
Name = secure-envoy-successful
  Vendor = Secure Envoy
  Product = Secure Envoy
  Lms = Direct
  DataType = ""authentication-successful""
  TimeFormat = "dd MM yyyy HH:mm:ss"
  Conditions = ["""TORVMVERIFY""","""Passcode OK"""]
  Fields = [
    """({time}\d+\s\w+\s\d+\s\d+:\d+:\d+)\s*""",
    """TORVMVERIFY01\s({server_name}[^\s]+)\sUserID=(({user}[^\s@]+?)@({domain}[^\s]+)|({=user}[^\s]+))\s({auth_method}Passcode OK)""",
    """ClientIP=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """RemoteID=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
	
  ]
}
```