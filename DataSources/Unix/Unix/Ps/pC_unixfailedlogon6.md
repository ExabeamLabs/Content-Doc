#### Parser Content
```Java
{
Name = unix-failed-logon-6
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """][""", """ sshd """, """ error: maximum authentication """ ]
  Fields = [
    """<\d{1,100}>\d{1,100} ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d) ({host}[\w.\-]{1,2000}) ({event_code}sshd)""",
    """({failure_reason}error: maximum authentication attempts exceeded) for (({domain}[^\\]{1,2000}?)\\+)?({user}[^\\]{1,2000}?) from """,
    """\sfrom ({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sport ({src_port}\d{1,100})""",
  ]
}
```