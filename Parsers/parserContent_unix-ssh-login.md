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
    """\d\d:\d\d:\d\d ({host}[^\s]+) SSH:""",
    """Listener=({dest_ip}[\da-fA-F:\.]+):({dest_port}\d+),""",
    """Client=({src_ip}[\da-fA-F:\.]+):({src_port}\d+),""",
    """User=({user}[^>]+)""",
    """Host=({dest_host}[^,]+)""",
    """SSH: ({event_name}[^<]+)\s+<""",
    """({event_code}SSH)"""
  ]
}
```