#### Parser Content
```Java
{
Name = json-5158
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-network-bind"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"EventID":5158,""", """The Windows Filtering Platform has permitted a bind to a local port""" ]
  Fields = [
    """({event_code}5158)""",
    """({event_name}The Windows Filtering Platform has permitted a bind to a local port)""",
    """"EventTime"+:"+({time}[^",]+)""",
    """"Hostname"+:"+({host}[^",]+)""",
    """"ProcessId"+:"+({pid}[^"]+)""",
    """"Application"+:"+({process}({directory}[^,"]*?[\\\/]+)?({process_name}[^\\\/\s"]+?))"""",
    """"SourceAddress"+:"+({dest_ip}[a-fA-F:\d.]+)""",
    """"SourcePort"+:"+({dest_port}\d+)""",
    """"Protocol"+:"+({ms_protocol_num}[^"]+)""",
    """Layer Name:(?:\s|\\t|\\n|\\r)*({layer_name}[^:]+?)(?:\s|\\t|\\n|\\r)*Layer Run-Time ID:"""
    """(?i)\w+\s*\d+\s*\d+:\d+:\d+\s+(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|({dest_host}[\w\-.]+)))"""
  ]
  DupFields = [ "host->dest_host" ]
}
```