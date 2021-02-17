#### Parser Content
```Java
{
Name = unix-authentication-failed-1
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """failed pam web login:""" ]
  Fields = [
    """\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S+\s+({host}[^\s]+)\s+({process_name}[^\s]+)\s+({process_id}\d+)\s""",
    """web login:\s({user}[^\s@]+)@({src_ip}[\da-fA-F.:]+)""",
    """({outcome}failed)""",
  ]
}
```