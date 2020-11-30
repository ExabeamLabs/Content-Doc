#### Parser Content
```Java
{
Name = unix-remote-logon-1
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """channel: SFTP subsystem started in channel""", """c_Window: """, """c_MaxPacket: """, """s_Window: """, """s_MaxPacket: """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[^\s]+) channel:""",
    """Listener=({dest_ip}[\da-fA-F:\.]+):({dest_port}\d+),""",
    """Client=({src_ip}[\da-fA-F:\.]+):({src_port}\d+),""",
    """User=({user}[^>]+)""",
    """Host=({dest_host}[^,]+)""",
    """channel: ({event_name}[^:]+?)\s+\w+:"""	
  ]
}
```