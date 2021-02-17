#### Parser Content
```Java
{
Name = f5-vpn-policy
  Vendor = F5
  Product = Big-IP
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """01490102:5:""", """Access policy result:""" ]
  Fields = [
    """\s+01490102:5:\s+({session_id}[^:]+)""",
    """\sAccess policy result:\s*({policy}.+?)\s*$""",
  ]
}
```