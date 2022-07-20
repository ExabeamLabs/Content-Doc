#### Parser Content
```Java
{
Name = cisco-process-created
  Vendor = Cisco
  Product = NPE
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CFGLOG_LOGGEDCMD:""", """logged command:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\w{1,10}\s{1,100}\d{1,2}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})\s""",
    """User:\s{0,100}({user}[^\s]{1,2000})""",
    """logged command:[\s\*]{0,2000}({command_line}({process_name}[^\s]{1,2000})?.+?)?[\s\*]{0,2000}(Source:\s{0,100}\/({dest_ip}[A-Fa-f:\d.]{1,2000})|$)""",
    """Original Address=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
  ]


}
```