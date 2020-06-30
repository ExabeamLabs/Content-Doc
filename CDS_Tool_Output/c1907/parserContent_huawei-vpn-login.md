#### Parser Content
```Java
{
Name = huawei-vpn-login
  Vendor = Huawei
  Product = Unified Security Gateway
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """SEC/""", """/SESSION""", """DevIP=""", """ VPN ID:""" ]
  Fields = [
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+(\+|\-)\d\d:\d\d),\S+\s+({host}[\w\.\-]+)""",
     """Protocol:({protocol}[^;]+)""",
     """({src_ip}[^\s;]+?):({src_port}\d+);\s*({src_translated_ip}[^\s;]+?):({src_translated_port}\d+);\s*-->({dest_ip}[^;]+?):({dest_port}\d+);""",
     """\sname:(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(({user_email}[^@;]+@[^@;]+)|({user}[^;]+));"""
  ]
}
```