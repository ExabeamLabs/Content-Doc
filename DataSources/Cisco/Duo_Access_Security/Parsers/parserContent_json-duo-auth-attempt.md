#### Parser Content
```Java
{
Name = json-duo-auth-attempt
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Direct
  DataType = "authentication-attempt"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [""""server_section":""", """"auth_stage":""", """authentication"""]
  Fields = [
    """exabeam_host=({host}[\w\-\.]{1,2000})""",
    """"username":\s{0,100}"(|({user}[^"]{1,2000}))"""",
    """"status":\s{0,100}"(|({outcome}[^"]{1,2000}))"""",
    """"client_ip":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """(?:("msg":\s{0,100}"(|({additional_info}[^"]{1,2000}))")|("status":\s{0,100}"Reject".+?"msg":\s{0,100}"(|({failure_reason}[^"]{1,2000}))"))""",
    """"timestamp":\s{0,100}"({time}\d{1,100}\-\d{1,100}\-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """"auth_stage":\s{0,100}"(|({auth_method}[^"]{1,2000}))"""",
    """({service}\w+[^\-"]{0,2000}?) authentication succeeded"""
  ]
}
```