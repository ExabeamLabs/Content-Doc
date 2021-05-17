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
    """\d\d:\d\d:\d\d ({host}[^\s]{1,2000}) channel:""",
    """Listener=({dest_ip}[\da-fA-F:\.]{1,2000}):({dest_port}\d{1,100}),""",
    """Client=({src_ip}[\da-fA-F:\.]{1,2000}):({src_port}\d{1,100}),""",
    """User=({user}[^>]{1,2000})""",
    """Host=({dest_host}[^,]{1,2000})""",
    """channel: ({event_name}[^:]{1,2000}?)\s{1,100}\w+:"""	
  ]
}
```