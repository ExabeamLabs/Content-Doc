#### Parser Content
```Java
{
Name = unix-failed-logon-4
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """][""", """ sshd """, """ Failed password for """ ]
  Fields = [
    """<\d{1,100}>\d{1,100} ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d) ({host}[\w.\-]+) sshd""",
    """Failed password for.+?user (({domain}[^\\]+?)\\+)?({user}[^\\]+?) from """,
    """\sfrom ({src_ip}[a-fA-F\d.:]+)""",
    """\sport ({src_port}\d{1,100})""",
  ]
}
```