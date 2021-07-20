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
    """({time}\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d \d\d\d\d)""",
    """\d\d:\d\d:\d\d \d\d\d\d ({host}[^\s]{1,2000})""",
    """({event_name}SSHS_CONNECT)""",
    """SSHS_CONNECT: ({user}[^\s]{1,2000})""",
    """IP: ({src_ip}[a-fA-F:\d\.]{1,2000})\)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```