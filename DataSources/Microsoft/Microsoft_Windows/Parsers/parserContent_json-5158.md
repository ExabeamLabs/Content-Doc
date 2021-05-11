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
    """"EventTime"{1,20}:"{1,20}({time}[^",]+)""",
    """"Hostname"{1,20}:"{1,20}({host}[^",]+)""",
    """"ProcessId"{1,20}:"{1,20}({pid}[^"]+)""",
    """"Application"{1,20}:"{1,20}({process}({directory}[^,"]*?[\\\/]+)?({process_name}[^\\\/\s"]+?))"""",
    """"SourceAddress"{1,20}:"{1,20}({dest_ip}[a-fA-F:\d.]+)""",
    """"SourcePort"{1,20}:"{1,20}({dest_port}\d{1,100})""",
    """"Protocol"{1,20}:"{1,20}({ms_protocol_num}[^"]+)""",
    """Layer Name:(?:\s|\\t|\\n|\\r)*({layer_name}[^:]+?)(?:\s|\\t|\\n|\\r)*Layer Run-Time ID:"""
    """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|({dest_host}[\w\-.]+)))"""
  ]
  DupFields = [ "host->dest_host" ]
}
```