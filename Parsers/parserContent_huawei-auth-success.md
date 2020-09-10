#### Parser Content
```Java
{
Name = huawei-auth-success
  Vendor = Huawei
  Product = Unified Security Gateway
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """HTTPD/""", """ User """, """ login succeeded""" ]
  Fields = [
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+(\+|\-)\d\d:\d\d),\S+\s+({host}[\w\.\-]+)""",
     """User ({user}[^\(]+)\(""",
     """IP:({src_ip}[a-fA-F\d.:]+)""",
     """\slogin ({outcome}succeeded)""",
  ]
}
```