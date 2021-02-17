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
    """,({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""",
    """pid=({process_id}\d+)""",
    """\suid=({user_id}\d+)""",
    """\sses=({session_id}\d+)""",
    """\sauid=({account_used_id}\d+)""",
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s"""
  ]
}
```