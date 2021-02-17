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
    """>\w+ \d\d \d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """"result":"({outcome}[^"]+)""",
    """"user":"({user}[^"]+)""",
    """"src_ip":"({src_ip}[a-fA-F\d.:]+)""",
    """"failure_reason":"({failure_reason}[^"]+)""",
    """"auth_method":"({auth_method}[^"]+)""",
    """"dst_host":"({dest_host}[^"]+)""",
    """({event_name}Login)""",
  ]
}
```