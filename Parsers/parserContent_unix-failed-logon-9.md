#### Parser Content
```Java
{
Name = unix-failed-logon-9
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """ sshd[""", """]: Login_Denied """ ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d.\d\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+""",
    """ip=({ip}[^\s:]+)""",
    """auth=({event_name}[^""]+)""",
    """apparentlyi_via=({logon_type_text}[^\s]+)""",
  ]
}
```