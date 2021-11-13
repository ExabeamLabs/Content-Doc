#### Parser Content
```Java
{
Name = xml-5158
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  DataType = "process-network-bind"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<EventID>5158</EventID>""", """<Event xmlns"""  ]
  Fields = [
    """<TimeCreated SystemTime\\{0,20}='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d{1,100}Z'/>""",
    """({event_code}5158)""",
    """<Computer>({host}[^<>]{1,2000}?)</Computer>""",
    """<Data Name\\{0,20}='ProcessId'>({pid}[^<>]{1,100})</Data>""",
    """<Data Name\\{0,20}='Application'>({process}({process_directory}(?:[^<]{1,2000})?[\\\/])?({process_name}[^\\\/]{1,2000}?))</Data>""",
    """<Data Name\\{0,20}='SourceAddress'>(::|({src_ip}[a-fA-F:\d.]{1,2000}))</Data>""",
    """<Data Name\\{0,20}='SourcePort'>({src_port}\d{1,100})</Data>""",
    """<Data Name\\{0,20}='DestAddress'>({dest_ip}[a-fA-F:\d.]{1,2000})</Data>""",
    """<Data Name\\{0,20}='DestPort'>({dest_port}\d{1,100})</Data>""",
    """<Data Name\\{0,20}='Protocol'>({ms_protocol_num}\d{1,100})</Data>""",
    """<Data Name\\{0,20}='LayerName'>\s{0,100}({layer_name}[^<]{1,2000}?)\s{0,100}</Data>"""
]
  DupFields = [ "host->dest_host" ]


}
```