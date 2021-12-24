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
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s(::ffff:)?({host}[\w\-.]{1,2000})\s""",
    """\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S{1,2000}\s{1,100}(::ffff:)?({host}[^\s]{1,2000})\s{1,100}({process_name}[^\s]{1,2000})\s{1,100}({process_id}\d{1,100})\s""",
    """({host}[\w\.\-]{1,2000})?:?\s{0,100}sudo:""",
    """ruser=({user}[^\s]{1,2000})""",
    """\suser=({user}[^\s"]{1,2000})(\s|"|$)""",
    """rhost=({src_ip}[\da-fA-F.:]{1,2000})""",
    """({failure_reason}authentication ({outcome}failure))""",
    """\suid=({user_id}[^\s]{1,2000})\s""",
    """({event_code}ssh)"""
  ]


}
```