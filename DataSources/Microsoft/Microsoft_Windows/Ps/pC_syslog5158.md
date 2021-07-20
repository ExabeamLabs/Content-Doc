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
    """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(am|pm|({host}[\w\-.]{1,2000}))""",
    """({time}\w+ \w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s{1,100}""",
    """({event_code}5158)""",
    """\WComputer\\*=(::ffff:)?({host}[\w\-.]{1,2000})""",
    """Computer(Name)?\s{0,100}\\*"?(=|:|>)\s{0,100}"{0,20}(::ffff:)?({host}[\w\.-]{1,2000})(\s|,|"|</Computer>|$)""",
    """({event_name}The Windows Filtering Platform has permitted a bind to a local port)""",
    """Process ID:\s{0,100}({pid}\d{1,100})""",
    """Application Name:\s{0,100}({process}({directory}.+)[\\\/]({process_name}.+?))\s{0,100}Network Information:""",
    """Source Address:\s{0,100}(0\.0\.0\.0|(::ffff:)?({dest_ip}(?!::)[a-fA-F:\d.]{1,2000}))?.+?\s{0,100}Source Port:\s{0,100}({dest_port}\d{0,100})""",
    """Protocol:\s{0,100}({ms_protocol_num}\d{0,100})""",
    """Layer Name:\s{0,100}({layer_name}.*?)\s{0,100}Layer Run-Time ID""",
    """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|({dest_host}[\w\-.]{1,2000})))"""
  ]
  DupFields = [ "host->dest_host" ]
}
```