#### Parser Content
```Java
{
Name = raw-5156
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-network"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """5156""", """The Windows Filtering Platform has permitted a connection""" ]
  Fields = [
    """Microsoft-Windows-Security-Auditing.*?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s{1,100}(::ffff:)?(am|AM|pm|PM|({host}[\w.\-]{1,2000}))""",
    """(?i)\w+ \d{1,100} \d\d:\d\d:\d\d (::ffff:)?(am|pm|({host}[\w\-.]{1,2000}))""",
    """\WComputer\\*=(::ffff:)?({host}[\w\-.]{1,2000})""",
    """\WComputerName:\s{0,100}(::ffff:)?({host}[\w\-.]{1,2000})""",
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s{1,100}""",
    """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s(::ffff:)?(am|pm|({host}[\w\-.]{1,2000}))""",
    """({event_code}5156)""",
    """({event_name}The Windows Filtering Platform has permitted a connection)""",
    """Process ID:\s{0,100}({pid}\d{1,100})""",
    """Application Name:\s{0,100}({process}({directory}.+)[\\\/]({process_name}.+?))\s{0,100}Network Information:""",
    """Direction:\s{0,100}({direction}Inbound).*Source Address:\s{0,100}(::ffff:)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{0,100}Source Port:\s{0,100}({dest_port}\d{0,100})\s{0,100}Destination Address:\s{0,100}(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{0,100}Destination Port:\s{0,100}({src_port}\d{0,100})""",
    """Direction:\s{0,100}({direction}Outbound).*Source Address:\s{0,100}(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{0,100}Source Port:\s{0,100}({src_port}\d{0,100})\s{0,100}Destination Address:\s{0,100}(::ffff:)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{0,100}Destination Port:\s{0,100}({dest_port}\d{0,100})"""
    """Protocol:\s{0,100}({ms_protocol_num}\d{0,100})""",
    """Layer Name:\s{0,100}({layer_name}[^\s]{0,2000})""",
  ]
}
```