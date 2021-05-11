#### Parser Content
```Java
{
Name = xml-5158
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "process-network-bind"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<EventID>5158</EventID>""", """<Event xmlns='"""  ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d{1,100}Z'/>""",
    """({event_code}5158)""",
    """<Computer>({host}[^<>]+?)</Computer>""",
    """<Data Name='ProcessId'>({pid}[^<>]+)</Data>""",
    """<Data Name='Application'>({process}({process_directory}(?:[^<]+)?[\\\/])?({process_name}[^\\\/]+?))</Data>""",
    """<Data Name='SourceAddress'>({src_ip}[a-fA-F:\d.]+)</Data>""",
    """<Data Name='SourcePort'>({src_port}\d{1,100})</Data>""",
    """<Data Name='DestAddress'>({dest_ip}[a-fA-F:\d.]+)</Data>""",
    """<Data Name='DestPort'>({dest_port}\d{1,100})</Data>""",
    """<Data Name='Protocol'>({ms_protocol_num}\d{1,100})</Data>""",
    """<Data Name='LayerName'>\s{0,100}({layer_name}.+?)\s{0,100}</Data>"""
]
  DupFields = [ "host->dest_host" ]
}
```