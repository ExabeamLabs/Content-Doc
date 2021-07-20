#### Parser Content
```Java
{
Name = unix-ssh-login
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """SSH: Completed password Authentication. User logged in""", """SessionID=""", """Listener=""", """Client=""", """<Host=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[^\s]{1,2000}) SSH:""",
    """Listener=({dest_ip}[\da-fA-F:\.]{1,2000}):({dest_port}\d{1,100}),""",
    """Client=({src_ip}[\da-fA-F:\.]{1,2000}):({src_port}\d{1,100}),""",
    """User=({user}[^>]{1,2000})""",
    """Host=({dest_host}[^,]{1,2000})""",
    """SSH: ({event_name}[^<]{1,2000})\s{1,100}<""",
    """({event_code}SSH)"""
  ]
}
```