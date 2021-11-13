#### Parser Content
```Java
{
Name = unix-remote-access
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "remote-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """FTP/SSL: logon success""", """SessionID=""", """Listener=""", """Client=""", """User=""", """<Host=""", """><Command=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[^\s]{1,2000}) FTP\/SSL:""",
    """Listener=({dest_ip}[\da-fA-F:\.]{1,2000}):({dest_port}\d{1,100})""",
    """Client=({src_ip}[\da-fA-F:\.]{1,2000}):({src_port}\d{1,100})""",
    """FTP\/SSL: ({event_name}[^\(]{1,2000})\s\(""",
    """SessionID=({session_id}\d{1,100})""",
    """Host=({dest_host}[^,=]{1,2000}?),\s{1,100}\w+=""",
    """User=({user}[^>=]{1,2000}?)><\w+="""
  ]


}
```