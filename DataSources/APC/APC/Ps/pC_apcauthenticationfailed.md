#### Parser Content
```Java
{
Name = apc-authentication-failed
  Vendor = APC
  Product = APC
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd 'time='HH:mm:ss.SSS"
  Conditions = [ """type=statistics """, """classifier="SMTP Auth Failure"""", """disposition="Reject"""" ]
  Fields = [
    """date=({time}\d\d\d\d-\d\d-\d\d\stime=\d\d:\d\d:\d\d\.\d{1,3})""",
    """client_name="({src_host}[^"]{1,2000}?)\s{0,100}"""",
    """client_ip="({src_ip}[a-fA-F\d:\.]{1,2000})"""",
    """dst_ip="({dest_ip}[a-fA-F\d:\.]{1,2000})"""",
    """from="({user}[^"]{1,2000})"""",
    """classifier="({event_name}[^"]{1,2000})"""",
    """disposition="({action}[^"]{1,2000})""""
  ]
  DupFields = [ "event_name->failure_reason" ]


}
```