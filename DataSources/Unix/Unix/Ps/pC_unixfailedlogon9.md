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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}""",
    """ip=({ip}[^\s:]{1,2000})""",
    """auth=({event_name}[^""]{1,2000})""",
    """apparentlyi_via=({logon_type_text}[^\s]{1,2000})""",
  ]


}
```