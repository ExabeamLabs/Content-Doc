#### Parser Content
```Java
{
Name = authmgr-authentication-failed-1
  DataType = "authentication-failed"
  Conditions = [ """client_ip_address=""", """result_action=Authorization Failure""" ]
  Fields = ${RSAParserTemplates.authmgr-authentication.Fields} [
    """,result_reason=({failure_reason}[^,]{1,2000}?)(\s{0,100}$|,)""",
  ]
}
authmgr-authentication = {
    Vendor = Dell
    Product = RSA Authentication Manager
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ss:SSS zzz"
    Fields = [
      """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d:\d{1,100} \w+),""",
      """,remote_client=({host}[^,]{1,2000}),""",
      """RSA:\s{0,100}({host}[^\s,]{1,2000}),""",
      """,user=({user}[^,\s]{1,2000})""",
      """,Resource=({additional_info}[^,]{1,2000}?)(\s{0,100}$|,)""",
      """,client_ip_address=({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """,browser_ip_address=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
      """,client_port=({src_port}\d{1,100})""",
      """,result_code=({result_code}\d{1,100})"""
    ]

```