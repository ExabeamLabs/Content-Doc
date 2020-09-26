#### Parser Content
```Java
{
Name = json-duo-auth-attempt
  Vendor = Duo Security
  Product = Duo Access Security
  Lms = Direct
  DataType = "authentication-attempt"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [""""server_section":""", """"auth_stage":""", """authentication"""]
  Fields = [
    """exabeam_host=({host}[\w\-\.]+)""",
    """"username":\s*"(|({user}[^"]+))"""",
    """"status":\s*"(|({outcome}[^"]+))"""",
    """"client_ip":\s*"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """(?:("msg":\s*"(|({additional_info}[^"]+))")|("status":\s*"Reject".+?"msg":\s*"(|({failure_reason}[^"]+))"))""",
    """"timestamp":\s*"({time}\d+\-\d+\-\d+T\d+:\d+:\d+\.\d+Z)""",
    """"auth_stage":\s*"(|({auth_method}[^"]+))"""",
    """({service}\w+[^\-"]*?) authentication succeeded"""
  ]
}
```