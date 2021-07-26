#### Parser Content
```Java
{
Name = f5-vpn-policy
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """01490102:5:""", """Access policy result:""" ]
  Fields = [
    """\s{1,100}01490102:5:\s{1,100}({session_id}[^:]{1,2000})""",
    """\s{1,100}01490102:5:.*?({session_id}[^\s:]{1,2000}): Access policy result""",
    """\sAccess policy result:\s{0,100}({policy}.+?)\s{0,100}$""",
  ]
}
```