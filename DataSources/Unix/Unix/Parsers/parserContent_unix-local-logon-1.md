#### Parser Content
```Java
{
Name = unix-local-logon-1
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "local-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """type=LOGIN""", """auid""" ]
  Fields = [
    """msg=audit\(({time}\d{10})""",
    """,({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""",
    """pid=({process_id}\d{1,100})""",
    """\suid=({user_id}\d{1,100})""",
    """\sses=({session_id}\d{1,100})""",
    """\sauid=({account_used_id}\d{1,100})""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s"""
  ]
}
```