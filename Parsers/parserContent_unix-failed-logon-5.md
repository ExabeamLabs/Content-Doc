#### Parser Content
```Java
{
Name = unix-failed-logon-5
  Vendor = Unix
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """][""", """ sshd """, """ Failed publickey for """ ]
  Fields = [
    """<\d+>\d+ ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d) ({host}[\w.\-]+) ({event_code}sshd)""",
    """({failure_reason}Failed publickey) for (({domain}[^\\]+?)\\+)?({user}[^\\]+?) from """,
    """\sfrom ({src_ip}[a-fA-F\d.:]+)""",
    """\sport ({src_port}\d+)""",
  ]
}
```