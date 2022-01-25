#### Parser Content
```Java
{
Name = huawei-vpn-login-1
  Vendor = Huawei
  Product = Unified Security Gateway
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """UM/""", """/LOGONSUCCESS""", """Source IP=""" ]
  Fields = [
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d),\S+\s{1,100}({host}[\w\.\-]{1,2000})""",
     """: User logon ({outcome}succeeded)""",
     """User Name=(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:unknown|({user_email}[^@,]{1,2000}@[^@,]{1,2000})|({user}[^,]{1,2000})),""",
     """Source IP=({src_ip}[a-fA-F\d.:]{1,2000})""",
  ]
  DupFields = ["user->account"]
}
```