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
    """Microsoft-Windows-Security-Auditing.*?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s+(::ffff:)?(am|AM|pm|PM|({host}[\w.\-]+))""",
    """(?i)\w+ \d+ \d\d:\d\d:\d\d (::ffff:)?(am|pm|({host}[\w\-.]+))""",
    """\WComputer\\*=(::ffff:)?({host}[\w\-.]+)""",
    """\WComputerName:\s*(::ffff:)?({host}[\w\-.]+)""",
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s+""",
    """(?i)\w+\s*\d+\s*\d+:\d+:\d+\s(::ffff:)?(am|pm|({host}[\w\-.]+))""",
    """({event_code}5156)""",
    """({event_name}The Windows Filtering Platform has permitted a connection)""",
    """Process ID:\s*({pid}\d+)""",
    """Application Name:\s*({process}({directory}.+)[\\\/]({process_name}.+?))\s*Network Information:""",
    """Direction:\s*({direction}Inbound).*Source Address:\s*(::ffff:)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*Source Port:\s*({dest_port}\d*)\s*Destination Address:\s*(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*Destination Port:\s*({src_port}\d*)""",
    """Direction:\s*({direction}Outbound).*Source Address:\s*(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*Source Port:\s*({src_port}\d*)\s*Destination Address:\s*(::ffff:)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*Destination Port:\s*({dest_port}\d*)"""
    """Protocol:\s*({ms_protocol_num}\d*)""",
    """Layer Name:\s*({layer_name}[^\s]*)""",
  ]
}
```