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
    """({time}\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d \d\d\d\d)""",
    """\d\d:\d\d:\d\d \d\d\d\d ({host}[^\s]{1,2000})""",
    """({event_name}SHELL_LOGIN)""",
    """SHELL_LOGIN: ({user}[^\s]{1,2000})""",
    """logged in from ({src_ip}[a-fA-F:\d\.]{1,2000})\."""
  ]
  DupFields = [ "host->dest_host" ]
}
```