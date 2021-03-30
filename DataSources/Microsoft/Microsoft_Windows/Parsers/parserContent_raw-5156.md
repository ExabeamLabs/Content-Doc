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
    """Microsoft-Windows-Security-Auditing.*?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s+({host}[\w.\-]+)""",
    """\w+ \d+ \d\d:\d\d:\d\d ({host}[\w\-.]+)""",
    """\WComputer\\*=({host}[\w\-.]+)""",
    """\WComputerName:\s*({host}[\w\-.]+)""",
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s+""",
    """({event_code}5156)""",
    """({event_name}The Windows Filtering Platform has permitted a connection)""",
    """Process ID:\s*({pid}\d+)""",
    """Application Name:\s*({process}({directory}.+)[\\\/]({process_name}.+?))\s*Network Information:""",
    """Direction:\s*({direction}Inbound).*Source Address:\s*({dest_ip}[^\s]*)\s*Source Port:\s*({dest_port}\d*)\s*Destination Address:\s*({src_ip}[^\s]*)\s*Destination Port:\s*({src_port}\d*)""",
    """Direction:\s*({direction}Outbound).*Source Address:\s*({src_ip}[^\s]*)\s*Source Port:\s*({src_port}\d*)\s*Destination Address:\s*({dest_ip}[^\s]*)\s*Destination Port:\s*({dest_port}\d*)""",
    """Protocol:\s*({ms_protocol_num}\d*)""",
    """Layer Name:\s*({layer_name}[^\s]*)""",
  ]
}
```