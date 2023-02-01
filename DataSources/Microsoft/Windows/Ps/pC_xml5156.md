#### Parser Content
```Java
{
Name = xml-5156
  Vendor = Microsoft
  Product = Windows
  Lms = Exabeam
  DataType = "process-network"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<EventID>5156</EventID>""", """<Event xmlns""" ]
  Fields = [
    """({event_name}The Windows Filtering Platform has permitted a connection)""",
    """<TimeCreated SystemTime\\{0,20}='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """({event_code}5156)""",
    """<Computer>({host}[^<>]{1,2000})<\/Computer>""",
    """<Data Name\\{0,20}='ProcessID'>({pid}[^<>]{1,100})<\/Data>""",
    """<Data Name\\{0,20}='Application'>({process}({process_directory}(?:[^<]{1,2000})?[\\\/])?({process_name}[^\\\/]{1,2000}?))<\/Data>""",
    """<Data Name\\{0,20}='SourceAddress'>({src_ip}[a-fA-F:\d.]{1,2000})<\/Data>""",
    """<Data Name\\{0,20}='SourcePort'>({src_port}\d{1,100})<\/Data>""",
    """<Data Name\\{0,20}='DestAddress'>({dest_ip}[a-fA-F:\d.]{1,2000})<\/Data>""",
    """<Data Name\\{0,20}='DestPort'>({dest_port}\d{1,100})<\/Data>""",
    """<Data Name\\{0,20}='Protocol'>({protocol}[^<>]{1,2000})<\/Data>""",
    """<\/Message>[^\n]{1,2000}?<Task>({activity_type}[^<>]{1,2000})<\/Task>""",
    """<Computer>({src_host}[^<>]{1,2000})<\/Computer>[^%]{1,2000}?%%14593<"""
    """Direction:\s{0,100}({direction}Outbound|Inbound)""",
    """<Computer>({dest_host}[^<>]{1,2000})<\/Computer>[^%]{1,2000}?%%14592<"""
    """Layer Name:\s{0,100}({layer_name}[^:]{1,2000}?)(\\[rn]|\s)"""
  ]
  DupFields = [ "host->local_asset" ]


}
```