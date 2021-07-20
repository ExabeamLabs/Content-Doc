#### Parser Content
```Java
{
Name = f5-vpn-username
  Vendor = F5
  Product = F5 BIG-IP Access Policy Manager (APM)
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """01490143:5:""", """username:""" ]
  Fields = [
    """:Common:({session_id}[^:]{1,2000})""",
    """\s{1,100}01490143:5:.*?({session_id}[^\s:]{1,2000}): Logging Agent""",
    """\susername:\s{1,100}({user}\S+)""",
  ]
}
```