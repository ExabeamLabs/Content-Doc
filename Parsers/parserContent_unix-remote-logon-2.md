#### Parser Content
```Java
{
Name = unix-remote-logon-2
  Vendor = Unix
  Product = Unix
  Lms = Syslog
  DataType = "remote-logon"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """logged in from """, """SHELL_LOGIN: """ ]
  Fields = [
    """({time}\w+\s+\d+ \d\d:\d\d:\d\d \d\d\d\d)""",
    """\d\d:\d\d:\d\d \d\d\d\d ({host}[^\s]+)""",
    """({event_name}SHELL_LOGIN)""",
    """SHELL_LOGIN: ({user}[^\s]+)""",
    """logged in from ({src_ip}[a-fA-F:\d\.]+)\."""
  ]
  DupFields = [ "host->dest_host" ]
}
```