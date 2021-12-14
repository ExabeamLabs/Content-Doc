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
    """\sdvchost=({host}[\w\-.]{1,2000})\s\w{1,2000}=""",
    """"hostname":\s{0,100}"({host}[\w\-.]{1,2000})"""",
    """"username":\s{0,100}"(|({user}[^"]{1,2000}))"""",
    """"status":\s{0,100}"(|({outcome}[^"]{1,2000}))"""",
    """"client_ip":\s{0,100}"({src_ip}[A-Fa-f\d:.]{1,2000})"""",
    """(("status":\s{0,100}"Reject"[^\}]{0,2000}"msg":\s{0,100}"({failure_reason}[^"]{1,2000}))|("msg":\s{0,100}"({additional_info}[^"]{1,2000})))"""",
    """"timestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,10}Z)""",
    """"auth_stage":\s{0,100}"(|({auth_method}[^"]{1,2000}))""""
  ]


}
```