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
    """\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S+\s{1,100}({host}[^\s]{1,2000})\s{1,100}({process_name}[^\s]{1,2000})\s{1,100}({process_id}\d{1,100})\s""",
    """web login:\s({user}[^\s@]{1,2000})@({src_ip}[\da-fA-F.:]{1,2000})""",
    """({outcome}failed)""",
  ]
}
```