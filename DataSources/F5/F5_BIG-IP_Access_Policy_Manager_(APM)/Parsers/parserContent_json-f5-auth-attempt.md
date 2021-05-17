#### Parser Content
```Java
{
Name = json-f5-auth-attempt
  Vendor = F5
  Product = F5 BIG-IP Access Policy Manager (APM)
  Lms = Direct
  DataType = "authentication-attempt"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"Login":""", """"failure_reason":"""", """"auth_method":"""", """"session_id":"""", """0149""", """:5:""" ]
  Fields = [
    """>\w+ \d\d \d\d:\d\d:\d\d ({host}[\w.\-]{1,2000})""",
    """"result":"({outcome}[^"]{1,2000})""",
    """"user":"({user}[^"]{1,2000})""",
    """"src_ip":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"failure_reason":"({failure_reason}[^"]{1,2000})""",
    """"auth_method":"({auth_method}[^"]{1,2000})""",
    """"dst_host":"({dest_host}[^"]{1,2000})""",
    """({event_name}Login)""",
  ]
}
```