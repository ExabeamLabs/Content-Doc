#### Parser Content
```Java
{
Name = cisco-process-created
  Vendor = Cisco
  Product = Cisco NPE
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CFGLOG_LOGGEDCMD:""", """logged command:""" ]
  Fields = [
    """({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """User:\s{0,100}({user}[^\s]+)""",
    """logged command:[\s\*]*({command_line}({process_name}[^\s]+)?.+?)?[\s\*]*(Source:\s{0,100}\/({dest_ip}[A-Fa-f:\d.]+)|$)""",
    """Original Address=({dest_ip}[A-Fa-f:\d.]+)""",
  ]
}
```