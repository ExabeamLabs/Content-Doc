#### Parser Content
```Java
{
Name = authmgr-authentication-failed-1
  DataType = "authentication-failed"
  Conditions = [ """client_ip_address=""", """result_action=Authorization Failure""" ]
  Fields = ${RSAParserTemplates.authmgr-authentication.Fields} [
    """,result_reason=({failure_reason}[^,]+?)(\s{0,100}$|,)""",
  ]
}
authmgr-authentication = {
    Vendor = Dell
    Product = RSA Authentication Manager
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ss:SSS zzz"
    Fields = [
      """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d:\d{1,100} \w+),""",
      """,remote_client=({host}[^,]+),""",
      """RSA:\s{0,100}({host}[^\s,]+),""",
      """,user=({user}[^,\s]+)""",
      """,Resource=({additional_info}[^,]+?)(\s{0,100}$|,)""",
      """,client_ip_address=({src_ip}[A-Fa-f:\d.]+)""",
      """,browser_ip_address=({dest_ip}[A-Fa-f:\d.]+)""",
      """,client_port=({src_port}\d{1,100})""",
      """,result_code=({result_code}\d{1,100})"""
    ]

```