#### Parser Content
```Java
{
Name = authmgr-authentication-failed
  DataType = "authentication-failed"
  Conditions = [ """client_ip_address=""", """result_action=Authentication Failure""" ]
  Fields = ${RSAParserTemplates.authmgr-authentication.Fields} [
    """,result_reason=({failure_reason}[^,]+?)(\s*$|,)""",
  ]
}
authmgr-authentication = {
    Vendor = Dell EMC
    Product = RSA Authentication Manager
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ss:SSS zzz"
    Fields = [
      """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d:\d+ \w+),""",
      """,remote_client=({host}[^,]+),""",
      """RSA:\s*({host}[^\s,]+),""",
      """,user=({user}[^,\s]+)""",
      """,Resource=({additional_info}[^,]+?)(\s*$|,)""",
      """,client_ip_address=({src_ip}[A-Fa-f:\d.]+)""",
      """,browser_ip_address=({dest_ip}[A-Fa-f:\d.]+)""",
      """,client_port=({src_port}\d+)""",
      """,result_code=({result_code}\d+)"""
    ]

```