#### Parser Content
```Java
{
Name = unix-remote-logon-3
  Vendor = Unix
  Product = Unix
  Lms = Syslog
  DataType = "remote-logon"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """SSH user""", """connected to """, """SSHS_CONNECT: """ ]
  Fields = [
    """({time}\w+\s+\d+ \d\d:\d\d:\d\d \d\d\d\d)""",
    """\d\d:\d\d:\d\d \d\d\d\d ({host}[^\s]+)""",
    """({event_name}SSHS_CONNECT)""",
    """SSHS_CONNECT: ({user}[^\s]+)""",
    """IP: ({src_ip}[a-fA-F:\d\.]+)\)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```