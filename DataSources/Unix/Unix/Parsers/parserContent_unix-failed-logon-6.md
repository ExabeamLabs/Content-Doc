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
    """<\d{1,100}>\d{1,100} ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d) ({host}[\w.\-]+) ({event_code}sshd)""",
    """({failure_reason}error: maximum authentication attempts exceeded) for (({domain}[^\\]+?)\\+)?({user}[^\\]+?) from """,
    """\sfrom ({src_ip}[a-fA-F\d.:]+)""",
    """\sport ({src_port}\d{1,100})""",
  ]
}
```