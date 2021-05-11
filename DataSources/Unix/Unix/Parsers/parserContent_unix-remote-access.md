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
    """\d\d:\d\d:\d\d ({host}[^\s]+) FTP\/SSL:""",
    """Listener=({dest_ip}[\da-fA-F:\.]+):({dest_port}\d{1,100})""",
    """Client=({src_ip}[\da-fA-F:\.]+):({src_port}\d{1,100})""",
    """FTP\/SSL: ({event_name}[^\(]+)\s\(""",
    """SessionID=({session_id}\d{1,100})""",
    """Host=({dest_host}[^,=]+?),\s{1,100}\w+=""",
    """User=({user}[^>=]+?)><\w+="""
  ]
}
```