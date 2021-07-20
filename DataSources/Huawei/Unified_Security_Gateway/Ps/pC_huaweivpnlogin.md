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
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d),\S+\s{1,100}({host}[\w\.\-]{1,2000})""",
     """Protocol:({protocol}[^;]{1,2000})""",
     """({src_ip}[^\s;]{1,2000}?):({src_port}\d{1,100});\s{0,100}({src_translated_ip}[^\s;]{1,2000}?):({src_translated_port}\d{1,100});\s{0,100}-->({dest_ip}[^;]{1,2000}?):({dest_port}\d{1,100});""",
     """\sname:(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(({user_email}[^@;]{1,2000}@[^@;]{1,2000})|({user}[^;]{1,2000}));"""
  ]
  DupFields = ["user->account"]
}
```