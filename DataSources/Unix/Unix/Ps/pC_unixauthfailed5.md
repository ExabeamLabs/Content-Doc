#### Parser Content
```Java
{
Name = unix-auth-failed-5
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """authentication failure;""","""logname=""","""ruser""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S+\s{1,100}({host}[^\s]{1,2000})\s{1,100}({process_name}[^\s]{1,2000})\s{1,100}({process_id}\d{1,100})\s""",
    """({host}[\w\.\-]{1,2000})?:?\s{0,100}sudo:""",
    """ruser=({user}[^\s]{1,2000})""",
    """rhost=({src_ip}[\da-fA-F.:]{1,2000})""",
    """authentication ({outcome}failure)""",
  ]


}
```