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
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d),\S+\s{1,100}({host}[\w\.\-]+)""",
     """User ({user}[^\(]+)\(""",
     """IP:({src_ip}[a-fA-F\d.:]+)""",
     """\slogin ({outcome}succeeded)""",
  ]
}
```