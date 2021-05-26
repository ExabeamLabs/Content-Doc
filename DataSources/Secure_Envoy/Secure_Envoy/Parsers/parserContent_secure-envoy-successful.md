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
    """({time}\d{1,100}\s\w+\s\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100})\s{0,100}""",
    """TORVMVERIFY01\s({server_name}[^\s]{1,2000})\sUserID=(({user}[^\s@]{1,2000}?)@({domain}[^\s]{1,2000})|({=user}[^\s]{1,2000}))\s({auth_method}Passcode OK)""",
    """ClientIP=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """RemoteID=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
	
  ]
}
```