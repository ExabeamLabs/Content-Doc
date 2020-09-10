#### Parser Content
```Java
{
Name = cisco-process-created
  Vendor = Cisco
  Product = Cisco NPE
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Conditions = [ """CFGLOG_LOGGEDCMD:""", """logged command:""" ]
  Fields = [
    """({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d+)""",
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """User:\s*({user}[^\s]+)""",
    """logged command:[\s\*]*({command_line}({process_name}[^\s]+)?.+?)?[\s\*]*(Source:\s*\/({dest_ip}[A-Fa-f:\d.]+)|$)""",
    """Original Address=({dest_ip}[A-Fa-f:\d.]+)""",
  ]
}
```