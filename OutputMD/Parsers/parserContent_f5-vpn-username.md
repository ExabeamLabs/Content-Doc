#### Parser Content
```Java
{
Name = f5-vpn-username
  Vendor = F5 Networks
  Product = F5 BIG-IP Access Policy Manager (APM)
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """01490143:5:""", """username:""" ]
  Fields = [
    """:Common:({session_id}[^:]+)""",
    """\s+01490143:5:.*?({session_id}[^\s:]+): Logging Agent""",
    """\susername:\s+({user}\S+)""",
  ]
}
```