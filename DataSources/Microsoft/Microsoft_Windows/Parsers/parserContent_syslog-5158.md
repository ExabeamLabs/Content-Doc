#### Parser Content
```Java
{
Name = syslog-5158
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-network-bind"
  TimeFormat = "EEE MMM dd HH:mm:ss yyyy"
  Conditions = [ """5158""", """The Windows Filtering Platform has permitted a bind to a local port""" ]
  Fields = [
    """\w+\s*\d+\s*\d+:\d+:\d+\s+(::ffff:)?({host}[\w\-.]+)""",
    """({time}\w+ \w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s+""",
    """({event_code}5158)""",
    """\WComputer\\*=(::ffff:)?({host}[\w\-.]+)""",
    """Computer(Name)?\s*\\*"?(=|:|>)\s*"*(::ffff:)?({host}[\w\.-]+)(\s|,|"|</Computer>|$)""",
    """({event_name}The Windows Filtering Platform has permitted a bind to a local port)""",
    """Process ID:\s*({pid}\d+)""",
    """Application Name:\s*({process}({directory}.+)[\\\/]({process_name}.+?))\s*Network Information:""",
    """Source Address:\s*(0\.0\.0\.0|(::ffff:)?({dest_ip}(?!::)[a-fA-F:\d.]+))?.+?\s*Source Port:\s*({dest_port}\d*)""",
    """Protocol:\s*({ms_protocol_num}\d*)""",
    """Layer Name:\s*({layer_name}.*?)\s*Layer Run-Time ID""",
    """\w+\s*\d+\s*\d+:\d+:\d+\s+(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))""",
  ]
  DupFields = [ "host->dest_host" ]
}
```