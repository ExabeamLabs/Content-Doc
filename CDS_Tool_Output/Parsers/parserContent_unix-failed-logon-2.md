#### Parser Content
```Java
{
Name = unix-failed-logon-2
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat = "yyyy MMM dd HH:mm:ss"
  Conditions = [ """ <sshd> """, """<Failed password for """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """<({time}\d+\s+\w+\s+\d+\s+\d+:\d+:\d+)\s""",
    """({event_code}ssh)""",
    """<Failed password for ({user}[^\s]+)""",
    """ from ({src_ip}[A-Fa-f:\d.]+)""",
    """ port ({src_port}\d+)""",
    """\d+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\w+>\s+<({dest_host}[\w\-.]+)""",
  ]
}
```